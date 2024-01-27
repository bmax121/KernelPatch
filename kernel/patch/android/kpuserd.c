/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

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
#include <taskob.h>
#include <predata.h>
#include <accctl.h>
#include <asm/current.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <syscall.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <predata.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/umh.h>
#include <uapi/scdefs.h>

const char origin_rc_file[] = "/system/etc/init/atrace.rc";
const char replace_rc_file[] = "/dev/.atrace.rc";

static const char patch_rc[] = ""
                               "on late-init\n"
                               "    rm %s \n"
                               "on post-fs-data\n"
                               "    start logd\n"
                               "    exec -- " KPATCH_SHADOW_PATH " %s android_user init -k\n"
                               "    exec -- " KPATCH_SHADOW_PATH " %s android_user post-fs-data -k'\n"
                               "on nonencrypted\n"
                               "    exec -- " KPATCH_SHADOW_PATH " %s android_user services -k'\n"
                               "on property:vold.decrypt=trigger_restart_framework\n"
                               "    exec -- " KPATCH_SHADOW_PATH " %s android_user services -k'\n"
                               "on property:sys.boot_completed=1\n"
                               "    exec -- " KPATCH_SHADOW_PATH " %s android_user boot-completed -k'\n"
                               "\n"
                               "";

static const void *kernel_read_file(const char *path, loff_t *len)
{
    void *data = 0;
    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        log_boot("open file: %s error: %d\n", path, PTR_ERR(filp));
        goto out;
    }
    *len = vfs_llseek(filp, 0, SEEK_END);
    vfs_llseek(filp, 0, SEEK_SET);
    data = vmalloc(*len);
    loff_t pos = 0;
    kernel_read(filp, data, *len, &pos);
    filp_close(filp, 0);
out:
    return data;
}

static void load_config()
{
    set_priv_selinx_allow(current, 1);

    set_priv_selinx_allow(current, 0);
}

static void on_post_fs_data()
{
    static bool done = false;
    if (done) return;
    done = true;
    set_priv_selinx_allow(current, 1);
    load_config();
    set_priv_selinx_allow(current, 0);
}

static void on_second_stage()
{
}

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

    const char app_process[] = "/system/bin/app_process";
    static bool first_app_process = true;

    /* This applies to versions Android 10+ */
    static const char system_bin_init[] = "/system/bin/init";
    /* This applies to versions between Android 6 ~ 9  */
    static const char old_system_init[] = "/init";
    static bool init_second_stage_executed = false;

    if (!memcmp(filename->name, system_bin_init, sizeof(system_bin_init) - 1) ||
        !memcmp(filename->name, old_system_init, sizeof(old_system_init) - 1)) {
        for (int i = 1;; i++) {
            const char *__user p1 =
                get_user_arg_ptr((void *)args->args[filename_index + 1], (void *)args->args[filename_index + 2], i);
            if (!p1) break;
            if (!IS_ERR(p1)) {
                char arg[16] = { '\0' };
                if (strncpy_from_user_nofault(arg, p1, sizeof(arg)) <= 0) break;

                if (!strcmp(arg, "second_stage")) {
                    log_boot("0 exec %s second_stage\n", filename->name);
                    on_second_stage();
                    init_second_stage_executed = true;
                }
            }
        }

        if (!init_second_stage_executed) {
            int envp_index = filename_index + (has_config_compat ? 3 : 2);
            for (int i = 0;; i++) {
                const char *__user up =
                    get_user_arg_ptr((void *)args->args[envp_index], (void *)args->args[envp_index + 1], i);
                if (!up || IS_ERR(up)) break;
                char env[256];
                if (strncpy_from_user_nofault(env, up, sizeof(env)) <= 0) break;

                // Parsing environment variable names and values
                char *env_name = env;
                char *env_value = strchr(env, '=');
                if (env_value) {
                    // Replace equal sign with string terminator
                    *env_value = '\0';
                    env_value++;
                    // Check if the environment variable name and value are matching
                    if (!strcmp(env_name, "INIT_SECOND_STAGE") &&
                        (!strcmp(env_value, "1") || !strcmp(env_value, "true"))) {
                        log_boot("1 exec %s second_stage\n", filename->name);
                        on_second_stage();
                        init_second_stage_executed = true;
                    }
                }
            }
        }
    }

    if (unlikely(first_app_process && !memcmp(filename->name, app_process, sizeof(app_process) - 1))) {
        first_app_process = false;
        log_boot("exec app_process, /data prepared, second_stage: %d\n", init_second_stage_executed);
        on_post_fs_data();
        remove_execv_hook(before_do_execve, 0);
    }
}

static void after_openat(hook_fargs4_t *args, void *udata);

static void before_openat(hook_fargs4_t *args, void *udata)
{
    // clear local
    args->local.data0 = 0;

    static bool replaced = false;
    if (replaced) return;

    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[32];
    strncpy_from_user_nofault(buf, filename, sizeof(buf));
    if (strcmp(origin_rc_file, buf)) return;

    replaced = true;

    set_priv_selinx_allow(current, 1);
    // create replace file and redirect
    loff_t ori_len = 0;
    struct file *newfp = filp_open(replace_rc_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(newfp)) {
        log_boot("create replace rc error: %d\n", PTR_ERR(newfp));
        goto out;
    }
    const char *ori_rc_data = kernel_read_file(origin_rc_file, &ori_len);
    if (!ori_rc_data) goto out;
    char *replace_rc_data = vmalloc(sizeof(patch_rc) + sizeof(replace_rc_file) + 5 * SUPER_KEY_LEN);
    const char *superkey = get_superkey();
    sprintf(replace_rc_data, patch_rc, replace_rc_file, superkey, superkey, superkey, superkey, superkey);
    loff_t off = 0;
    kernel_write(newfp, replace_rc_data, strlen(replace_rc_data), &off);
    kernel_write(newfp, ori_rc_data, ori_len, &off);
    if (off != strlen(replace_rc_data) + ori_len) {
        log_boot("write replace rc error: %x\n", off);
        goto free;
    }
    // yes, filename is not read only
    args->local.data0 = seq_copy_to_user((void *)filename, replace_rc_file, sizeof(replace_rc_file));
    log_boot("redirect rc file: %x\n", args->local.data0);
free:
    filp_close(newfp, 0);
    kvfree(ori_rc_data);
    kvfree(replace_rc_data);
out:
    // read file not require selinux permission, reset not allow now
    set_priv_selinx_allow(current, 0);
    return;
}

static void after_openat(hook_fargs4_t *args, void *udata)
{
    if (args->local.data0) {
        const char __user *filename = (typeof(filename))syscall_argn(args, 1);
        int len = seq_copy_to_user((void *)filename, origin_rc_file, sizeof(origin_rc_file));
        log_boot("restore rc file: %x\n", len);
        // todo:
        fp_unhook_syscall(__NR_openat, before_openat, after_openat);
    }
}

#define EV_KEY 0x01
#define KEY_VOLUMEDOWN 114

// void input_handle_event(struct input_dev *dev, unsigned int type, unsigned int code, int value)
static void before_input_handle_event(hook_fargs4_t *args, void *udata)
{
    static unsigned int volumedown_pressed_count = 0;
    unsigned int type = args->arg1;
    unsigned int code = args->arg2;
    int value = args->arg3;
    if (value && type == EV_KEY && code == KEY_VOLUMEDOWN) {
        volumedown_pressed_count++;
        if (volumedown_pressed_count == 3) {
            log_boot("entering safemode ...");
            struct file *filp = filp_open(SAFE_MODE_FLAG_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (filp && !IS_ERR(filp)) filp_close(filp, 0);
        }
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

    fp_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);

    unsigned long input_handle_event_addr = get_preset_patch_sym()->input_handle_event;
    if (!input_handle_event_addr) {
        log_boot("no symbol input_handle_event_addr\n");
        rc = -ENOENT;
        goto out;
    } else {
        hook_err_t err = hook_wrap4((void *)input_handle_event_addr, before_input_handle_event, 0, 0);
        if (err) {
            log_boot("hook do_faccessat error: %d\n", err);
            rc = err;
            goto out;
        }
    }

out:
    return rc;
}