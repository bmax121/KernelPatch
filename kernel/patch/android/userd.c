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
#include <symbol.h>
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
#include <uapi/linux/stat.h>

#define ORIGIN_RC_FILE "/system/etc/init/hw/init.rc"
#define REPLACE_RC_FILE "/dev/user_init.rc"

#define ADB_FLODER "/data/adb/"
#define AP_DIR "/data/adb/ap/"
#define DEV_LOG_DIR "/dev/user_init_log/"
#define AP_BIN_DIR AP_DIR "bin/"
#define AP_LOG_DIR AP_DIR "log/"
#define AP_MAGISKPOLICY_PATH AP_BIN_DIR "magiskpolicy"
#define MAGISK_SCTX "u:r:magisk:s0"
#define USER_INIT_SH_PATH "/dev/user_init.sh"

#include "gen/user_init.c"

static const char user_rc_data[] = { //
    "\n"
    "on early-init\n"
    "    exec -- " SUPERCMD " su exec " USER_INIT_SH_PATH " %s early-init\n"
    "on init\n"
    "    exec -- " SUPERCMD " su exec " USER_INIT_SH_PATH " %s init\n"
    "on late-init\n"
    "    exec -- " SUPERCMD " su exec " USER_INIT_SH_PATH " %s late-init\n"
    "on post-fs-data\n"
    "    exec -- " SUPERCMD " su exec " USER_INIT_SH_PATH " %s post-fs-data\n"
    "on nonencrypted\n"
    "    exec -- " SUPERCMD " su exec " USER_INIT_SH_PATH " %s services\n"
    "on property:vold.decrypt=trigger_restart_framework\n"
    "    exec -- " SUPERCMD " su exec " USER_INIT_SH_PATH " %s services\n"
    "on property:sys.boot_completed=1\n"
    "    exec -- " SUPERCMD " su exec " USER_INIT_SH_PATH " %s boot-completed\n"
    "    rm " REPLACE_RC_FILE "\n"
    "    rm " USER_INIT_SH_PATH "\n"
    "    exec -- " SUPERCMD " su -c \"mv -f " DEV_LOG_DIR " " AP_LOG_DIR "\"\n"
    ""
};

static const void *kernel_read_file(const char *path, loff_t *len)
{
    set_priv_sel_allow(current, true);
    void *data = 0;

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
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
    set_priv_sel_allow(current, false);
    return data;
}

static loff_t kernel_write_file(const char *path, const void *data, loff_t len, umode_t mode)
{
    loff_t off = 0;
    set_priv_sel_allow(current, true);

    struct file *fp = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (!fp || IS_ERR(fp)) {
        log_boot("create file %s error: %d\n", path, PTR_ERR(fp));
        goto out;
    }
    kernel_write(fp, data, len, &off);
    if (off != len) {
        log_boot("write file %s error: %x\n", path, off);
        goto free;
    }

free:
    filp_close(fp, 0);

out:
    set_priv_sel_allow(current, false);
    return off;
}

static void pre_user_exec_init()
{
    log_boot("event: %s\n", EXTRA_EVENT_PRE_EXEC_INIT);
    kernel_write_file(USER_INIT_SH_PATH, user_init, sizeof(user_init), 0700);
}

static void pre_init_second_stage()
{
    log_boot("event: %s\n", EXTRA_EVENT_PRE_SECOND_STAGE);
}

static void on_first_app_process()
{
}

static void handle_before_execve(hook_local_t *hook_local, char **__user u_filename_p, char **__user uargv,
                                 char **__user uenvp, void *udata)
{
    // unhook flag
    hook_local->data7 = 0;

    static char app_process[] = "/system/bin/app_process";
    static char app_process64[] = "/system/bin/app_process64";
    static int first_app_process_execed = 0;

    static const char system_bin_init[] = "/system/bin/init";
    static const char root_init[] = "/init";
    static int first_user_init_executed = 0;
    static int init_second_stage_executed = 0;

    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(system_bin_init, filename) || !strcmp(root_init, filename)) {
        //
        if (!first_user_init_executed) {
            first_user_init_executed = 1;
            log_boot("exec first user init: %s\n", filename);
            pre_user_exec_init();
        }

        if (!init_second_stage_executed) {
            for (int i = 1;; i++) {
                const char __user *p1 = get_user_arg_ptr(0, *uargv, i);
                if (!p1 || IS_ERR(p1)) break;

                char arg[16] = { '\0' };
                if (compat_strncpy_from_user(arg, p1, sizeof(arg)) <= 0) break;

                if (!strcmp(arg, "second_stage") || !strcmp(arg, "--second-stage")) {
                    log_boot("exec %s second stage 0\n", filename);
                    pre_init_second_stage();
                    init_second_stage_executed = 1;
                }
            }
        }

        if (!init_second_stage_executed) {
            for (int i = 0;; i++) {
                const char *__user uenv = get_user_arg_ptr(0, *uenvp, i);
                if (!uenv || IS_ERR(uenv)) break;

                char env[256];
                if (compat_strncpy_from_user(env, uenv, sizeof(env)) <= 0) break;
                char *env_name = env;
                char *env_value = strchr(env, '=');
                if (env_value) {
                    *env_value = '\0';
                    env_value++;
                    if (!strcmp(env_name, "INIT_SECOND_STAGE") &&
                        (!strcmp(env_value, "1") || !strcmp(env_value, "true"))) {
                        log_boot("exec %s second stage 1\n", filename);
                        pre_init_second_stage();
                        init_second_stage_executed = 1;
                    }
                }
            }
        }
    }

    if (!first_app_process_execed && (!strcmp(app_process, filename) || !strcmp(app_process64, filename))) {
        first_app_process_execed = 1;
        log_boot("exec first app_process: %s\n", filename);
        on_first_app_process();
        hook_local->data7 = 1;
        return;
    }
}

static void before_execve(hook_fargs3_t *args, void *udata);
static void after_execve(hook_fargs3_t *args, void *udata);
static void before_execveat(hook_fargs5_t *args, void *udata);
static void after_execveat(hook_fargs5_t *args, void *udata);

static void handle_after_execve(hook_local_t *hook_local)
{
    int unhook = hook_local->data7;
    if (unhook) {
        unhook_syscalln(__NR_execve, before_execve, after_execve);
        unhook_syscalln(__NR_execveat, before_execveat, after_execveat);
    }
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2087
// SYSCALL_DEFINE3(execve, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp)
static void before_execve(hook_fargs3_t *args, void *udata)
{
    void *arg0p = syscall_argn_p(args, 0);
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    handle_before_execve(&args->local, (char **)arg0p, (char **)arg1p, (char **)arg2p, udata);
}

static void after_execve(hook_fargs3_t *args, void *udata)
{
    handle_after_execve(&args->local);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2095
// SYSCALL_DEFINE5(execveat, int, fd, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp, int, flags)
static void before_execveat(hook_fargs5_t *args, void *udata)
{
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    void *arg3p = syscall_argn_p(args, 3);
    handle_before_execve(&args->local, (char **)arg1p, (char **)arg2p, (char **)arg3p, udata);
}

static void after_execveat(hook_fargs5_t *args, void *udata)
{
    handle_after_execve(&args->local);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/open.c#L1337
// SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, umode_t, mode)
static void before_openat(hook_fargs4_t *args, void *udata)
{
    // cp len
    args->local.data0 = 0;
    // cp ptr
    args->local.data1 = 0;
    // unhook flag
    args->local.data2 = 0;

    static int replaced = 0;
    if (replaced) return;

    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[32];
    long rc = compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (rc <= 0) return;
    if (strcmp(ORIGIN_RC_FILE, buf)) return;

    replaced = 1;

    loff_t ori_len = 0;
    struct file *newfp = filp_open(REPLACE_RC_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (!newfp || IS_ERR(newfp)) {
        log_boot("create replace rc error: %d\n", PTR_ERR(newfp));
        goto out;
    }

    loff_t off = 0;
    const char *ori_rc_data = kernel_read_file(ORIGIN_RC_FILE, &ori_len);
    if (!ori_rc_data) goto out;
    kernel_write(newfp, ori_rc_data, ori_len, &off);
    if (off != ori_len) {
        log_boot("write replace rc error: %x\n", off);
        goto free;
    }

    char added_rc_data[4096];
    const char *sk = get_superkey();
    sprintf(added_rc_data, user_rc_data, sk, sk, sk, sk, sk, sk, sk);

    kernel_write(newfp, added_rc_data, strlen(added_rc_data), &off);
    if (off != strlen(added_rc_data) + ori_len) {
        log_boot("write replace rc error: %x\n", off);
        goto free;
    }

    int cplen = 0;
    cplen = compat_copy_to_user((void *)filename, REPLACE_RC_FILE, sizeof(REPLACE_RC_FILE));
    if (cplen > 0) {
        args->local.data0 = cplen;
        args->local.data1 = (uint64_t)args->arg1;
        log_boot("redirect rc file: %x\n", args->local.data0);
    } else {
        void *__user up = copy_to_user_stack(REPLACE_RC_FILE, sizeof(REPLACE_RC_FILE));
        args->arg1 = (uint64_t)up;
        log_boot("redirect rc file stack: %llx\n", up);
    }

free:
    filp_close(newfp, 0);
    kvfree(ori_rc_data);

out:
    args->local.data2 = 1;
    return;
}

static void after_openat(hook_fargs4_t *args, void *udata)
{
    if (args->local.data0) {
        compat_copy_to_user((void *)args->local.data1, ORIGIN_RC_FILE, sizeof(ORIGIN_RC_FILE));
        log_boot("restore rc file: %x\n", args->local.data0);
    }
    if (args->local.data2) {
        unhook_syscalln(__NR_openat, before_openat, after_openat);
    }
}

#define EV_KEY 0x01
#define KEY_VOLUMEDOWN 114

int android_is_safe_mode = 0;
KP_EXPORT_SYMBOL(android_is_safe_mode);

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
            android_is_safe_mode = 1;
        }
    }
}

int android_user_init()
{
    hook_err_t ret = 0;
    hook_err_t rc = HOOK_NO_ERR;

    rc = hook_syscalln(__NR_execve, 3, before_execve, after_execve, (void *)__NR_execve);
    log_boot("hook __NR_execve rc: %d\n", rc);
    ret |= rc;

    rc = hook_syscalln(__NR_execveat, 5, before_execveat, after_execveat, (void *)__NR_execveat);
    log_boot("hook __NR_execveat rc: %d\n", rc);
    ret |= rc;

    rc = hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    log_boot("hook __NR_openat rc: %d\n", rc);
    ret |= rc;

    unsigned long input_handle_event_addr = patch_config->input_handle_event;
    if (input_handle_event_addr) {
        rc = hook_wrap4((void *)input_handle_event_addr, before_input_handle_event, 0, 0);
        ret |= rc;
        log_boot("hook input_handle_event rc: %d\n", rc);
    }

    return ret;
}
