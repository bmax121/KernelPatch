#include <ktypes.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm-generic/compat.h>
#include <uapi/asm-generic/errno.h>
#include <syscall.h>
#include <kconfig.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <minc/string.h>
#include <taskob.h>
#include <predata.h>
#include <accctl.h>
#include <asm/current.h>
#include <linux/printk.h>
#include <module.h>

struct module *find_module(const char *name);

static void load_kpuserd_config()
{
    // todo: private allow
    set_selinx_allow(current, 1);

    patch_config_t *config = get_preset_patch_cfg();
    const char *su_config_path = config->config_ini_path;

    log_boot("config path: %s\n", su_config_path);

    // struct file *filp = filp_open(kpm_path, O_RDONLY, 0);
    // if (IS_ERR(filp)) {
    //     log_boot("open: %s error: %d\n", kpm_path, PTR_ERR(filp));
    //     goto out;
    // }

    // filp_close(filp, 0);
    // out:
    set_selinx_allow(current, 0);
}

static void on_post_fs_data()
{
    static bool done = false;
    if (done) {
        logkw("on_post_fs_data already done\n");
        return;
    }
    done = true;
    load_kpuserd_config();
}

#define CONFIG_COMPAT

struct user_arg_ptr
{
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union
    {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};
static const char __user *get_user_arg_ptr(void *a0, void *a1, int nr)
{
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) {
            native = (char __user *const __user *)((unsigned long)a1 >> 32);
            size = 4;
        }
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    char __user **upptr = memdup_user(native, size);
    if (IS_ERR(upptr)) {
        return ERR_PTR((long)upptr);
    }
    char __user *uptr;
    if (size == 8) {
        uptr = *upptr;
    } else {
        uptr = (char __user *)(unsigned long)*(int32_t *)upptr;
    }
    kfree(upptr);
    return uptr;
}

/*
Copied and modified from KernelSU, GPLv2
https://github.com/tiann/KernelSU
*/

// int do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
// int __do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags,
//                      struct file *file);
// static int do_execve_common(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp)
static void before_do_execve(hook_fargs8_t *args, void *udata)
{
    int filename_index = 0;
    if ((((uintptr_t)args->arg0) & 0xF000000000000000) != 0xF000000000000000) {
        filename_index = 1;
    }
    struct filename *filename = (struct filename *)args->args[filename_index];

    if (!filename || IS_ERR(filename)) return;

    static const char app_process[] = "/system/bin/app_process";
    static bool first_app_process = true;

    /* This applies to versions Android 10+ */
    static const char system_bin_init[] = "/system/bin/init";
    /* This applies to versions between Android 6 ~ 9  */
    static const char old_system_init[] = "/init";
    static bool init_second_stage_executed = false;

    if (!memcmp(filename->name, system_bin_init, sizeof(system_bin_init) - 1) ||
        !memcmp(filename->name, old_system_init, sizeof(old_system_init) - 1)) {
        for (int i = 1; i < 0x7FFFFFFF; i++) {
            const char __user *p1 =
                get_user_arg_ptr((void *)args->args[filename_index + 1], (void *)args->args[filename_index + 2], i);

            if (p1 && !IS_ERR(p1)) {
                char arg[16] = { '\0' };
                if (strncpy_from_user_nofault(arg, p1, sizeof(arg)) <= 0) {
                    break;
                }
                if (!min_strcmp(arg, "second_stage")) {
                    logkd("exec %s second_stage\n", filename->name);
                    init_second_stage_executed = true;
                    //  apply_kernelsu_rules();
                    //  ksu_android_ns_fs_check();
                }
            }
        }

        if (!init_second_stage_executed) {
            int envp_index = filename_index + (has_config_compat ? 3 : 2);
            for (int i = 0; i < 0x7FFFFFFF; i++) {
                const char __user *up =
                    get_user_arg_ptr((void *)args->args[envp_index], (void *)args->args[envp_index + 1], i);
                if (!up || IS_ERR(up)) break;
                char env[256];
                if (strncpy_from_user_nofault(env, up, sizeof(env)) <= 0) {
                    break;
                }
                // Parsing environment variable names and values
                char *env_name = env;
                char *env_value = min_strchr(env, '=');
                if (env_value) {
                    // Replace equal sign with string terminator
                    *env_value = '\0';
                    env_value++;
                    // Check if the environment variable name and value are matching
                    if (!strcmp(env_name, "INIT_SECOND_STAGE") &&
                        (!strcmp(env_value, "1") || !strcmp(env_value, "true"))) {
                        logkd("exec %s second_stage\n", filename->name);
                        init_second_stage_executed = true;
                        // apply_kernelsu_rules();
                        // ksu_android_ns_fs_check();
                    }
                }
            }
        }
    }

    if (unlikely(first_app_process && !memcmp(filename->name, app_process, sizeof(app_process) - 1))) {
        first_app_process = false;
        logkd("exec app_process, /data prepared, second_stage: %d\n", init_second_stage_executed);
        on_post_fs_data();
        remove_execv_hook(before_do_execve, 0);
    }
}

int kpuserd_init()
{
    int rc = 0;
    hook_err_t err = add_execv_hook(before_do_execve, 0, 0);
    if (err) {
        log_boot("hook add execv error: %d\n", err);
        rc = err;
        goto out;
    }
out:
    return rc;
}