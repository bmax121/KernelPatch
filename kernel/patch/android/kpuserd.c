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

#define ORIGIN_RC_FILE "/system/etc/init/atrace.rc"
#define REPLACE_RC_FILE "/dev/.atrace.rc"

static const char patch_rc[] =
    ""
    "\n"
    "on late-init\n"
    "    rm " REPLACE_RC_FILE "\n"
    "on post-fs-data\n"
    "    exec -- " KPATCH_SHADOW_PATH " %s " KPATCH_DEV_PATH " %s android_user post-fs-data-init -k\n"
    "    exec -- " KPATCH_SHADOW_PATH " %s " KPATCH_PATH " %s android_user post-fs-data -k\n"
    "on nonencrypted\n"
    "    exec -- " KPATCH_SHADOW_PATH " %s " KPATCH_PATH " %s android_user services -k\n"
    "on property:vold.decrypt=trigger_restart_framework\n"
    "    exec -- " KPATCH_SHADOW_PATH " %s " KPATCH_PATH " %s android_user services -k\n"
    "on property:sys.boot_completed=1\n"
    "    exec -- " KPATCH_SHADOW_PATH " %s " KPATCH_PATH " %s android_user boot-completed -k\n"
    "\n\n"
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

static void kernel_write_file(const char *path, const void *data, loff_t len, umode_t mode)
{
    set_priv_selinx_allow(current, 1);
    struct file *fp = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (IS_ERR(fp)) {
        log_boot("create file %s error: %d\n", path, PTR_ERR(fp));
        goto out;
    }
    loff_t off = 0;
    kernel_write(fp, data, len, &off);
    if (off != len) {
        log_boot("write file %s error: %x\n", path, off);
        goto free;
    }
free:
    filp_close(fp, 0);
out:
    set_priv_selinx_allow(current, 0);
}

static void kernel_write_exec(const char *path, const void *data, loff_t len)
{
    kernel_write_file(path, data, len, 0744);
}

static int extract_kpatch_call_back(const patch_extra_item_t *extra, const char *arg, const void *con, void *udata)
{
    const char *path = (const char *)udata;
    if (extra->type == EXTRA_TYPE_EXEC && !strcmp("kpatch", extra->name)) {
        log_boot("write kpatch to %s\n", path);
        kernel_write_exec(path, con, extra->con_size);
    }
    return 0;
}

static void before_first_stage()
{
    const char *path = KPATCH_DEV_PATH;
    on_each_extra_item(extract_kpatch_call_back, (void *)path);
}

static void before_second_stage()
{
}

static void on_zygote_start()
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
    static int first_app_process = 1;

    static const char system_bin_init[] = "/system/bin/init";
    static const char root_init[] = "/init";
    static int init_first_stage_executed = 0;
    static int init_second_stage_executed = 0;

    if (!strcmp(system_bin_init, filename->name) || !strcmp(root_init, filename->name)) {
        //
        if (!init_first_stage_executed) {
            init_first_stage_executed = 1;
            log_boot("exec %s first stage\n", filename->name);
            before_first_stage();
        }

        if (!init_second_stage_executed) {
            for (int i = 1;; i++) {
                const char *__user p1 =
                    get_user_arg_ptr((void *)args->args[filename_index + 1], (void *)args->args[filename_index + 2], i);
                if (!p1) break;
                if (!IS_ERR(p1)) {
                    char arg[16] = { '\0' };
                    if (strncpy_from_user_nofault(arg, p1, sizeof(arg)) <= 0) break;
                    if (!strcmp(arg, "second_stage") || !strcmp(arg, "--second-stage")) {
                        log_boot("exec %s second stage 0\n", filename->name);
                        before_second_stage();
                        init_second_stage_executed = 1;
                    }
                }
            }
        }

        if (!init_second_stage_executed) {
            int envp_index = filename_index + (has_config_compat ? 3 : 2);
            for (int i = 0;; i++) {
                const char *__user up =
                    get_user_arg_ptr((void *)args->args[envp_index], (void *)args->args[envp_index + 1], i);
                if (IS_ERR(up)) break;
                char env[256];
                if (strncpy_from_user_nofault(env, up, sizeof(env)) <= 0) break;
                char *env_name = env;
                char *env_value = strchr(env, '=');
                if (env_value) {
                    *env_value = '\0';
                    env_value++;
                    if (!strcmp(env_name, "INIT_SECOND_STAGE") &&
                        (!strcmp(env_value, "1") || !strcmp(env_value, "true"))) {
                        log_boot("exec %s second stage 1\n", filename->name);
                        before_second_stage();
                        init_second_stage_executed = 1;
                    }
                }
            }
        }
    }

    if (unlikely(first_app_process && !strcmp(app_process, filename->name))) {
        first_app_process = 0;
        log_boot("exec app_process, /data prepared, second_stage: %d\n", init_second_stage_executed);
        on_zygote_start();
        remove_execv_hook(before_do_execve, 0);
    }
}

static void after_openat(hook_fargs4_t *args, void *udata);

static void before_openat(hook_fargs4_t *args, void *udata)
{
    // clear local
    args->local.data0 = 0;

    static int replaced = 0;
    if (replaced) return;

    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[32];
    strncpy_from_user_nofault(buf, filename, sizeof(buf));
    if (strcmp(ORIGIN_RC_FILE, buf)) return;

    replaced = 1;

    set_priv_selinx_allow(current, 1);
    // create replace file and redirect
    loff_t ori_len = 0;
    struct file *newfp = filp_open(REPLACE_RC_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(newfp)) {
        log_boot("create replace rc error: %d\n", PTR_ERR(newfp));
        goto out;
    }
    const char *ori_rc_data = kernel_read_file(ORIGIN_RC_FILE, &ori_len);
    if (!ori_rc_data) goto out;
    char *replace_rc_data = vmalloc(sizeof(patch_rc) + 10 * SUPER_KEY_LEN);
    const char *superkey = get_superkey();
    sprintf(replace_rc_data, patch_rc, superkey, superkey, superkey, superkey, superkey, superkey, superkey, superkey,
            superkey, superkey);
    loff_t off = 0;
    kernel_write(newfp, replace_rc_data, strlen(replace_rc_data), &off);
    kernel_write(newfp, ori_rc_data, ori_len, &off);
    if (off != strlen(replace_rc_data) + ori_len) {
        log_boot("write replace rc error: %x\n", off);
        goto free;
    }
    // yes, filename is not read only
    args->local.data0 = seq_copy_to_user((void *)filename, REPLACE_RC_FILE, sizeof(REPLACE_RC_FILE));
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
        int len = seq_copy_to_user((void *)filename, ORIGIN_RC_FILE, sizeof(ORIGIN_RC_FILE));
        log_boot("restore rc file: %x\n", len);
        fp_unhook_syscall(__NR_openat, before_openat, after_openat);
    }
}

#define EV_KEY 0x01
#define KEY_VOLUMEDOWN 114

/* Modified from KernelSU */
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
            if (!IS_ERR(filp)) filp_close(filp, 0);
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