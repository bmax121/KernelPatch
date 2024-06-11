/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <hook.h>
#include <common.h>
#include <log.h>
#include <predata.h>
#include <pgtable.h>
#include <linux/syscall.h>
#include <uapi/asm-generic/errno.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <syscall.h>
#include <accctl.h>
#include <module.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <kputils.h>
#include <pidmem.h>
#include <predata.h>
#include <linux/random.h>
#include <sucompat.h>
#include <accctl.h>

#define MAX_KEY_LEN 128

#include <linux/umh.h>

static long call_test(long arg1, long arg2, long arg3)
{
    // char *cmd = "/system/bin/touch";
    // // const char *superkey = get_superkey();
    // char *argv[] = {
    //     cmd,
    //     "/data/local/tmp/test.txt",
    //     NULL,
    // };
    // char *envp[] = {
    //     "PATH=/system/bin:/data/adb",
    //     NULL,
    // };
    // int rc = call_usermodehelper(cmd, argv, envp, UMH_WAIT_PROC);
    // log_boot("user_init: %d\n", rc);
    return 0;
}

static long call_bootlog()
{
    print_bootlog();
    return 0;
}

static long call_panic()
{
    unsigned long panic_addr = kallsyms_lookup_name("panic");
    ((void (*)(const char *fmt, ...))panic_addr)("!!!! kernel_patch panic !!!!");
    return 0;
}

static long call_klog(const char __user *arg1)
{
    char buf[1024];
    long len = compat_strncpy_from_user(buf, arg1, sizeof(buf));
    if (len <= 0) return -EINVAL;
    if (len > 0) logki("user log: %s", buf);
    return 0;
}

static long call_kpm_load(const char __user *arg1, const char *__user arg2, void *__user reserved)
{
    char path[1024], args[KPM_ARGS_LEN];
    long pathlen = compat_strncpy_from_user(path, arg1, sizeof(path));
    if (pathlen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return load_module_path(path, arglen <= 0 ? 0 : args, reserved);
}

static long call_kpm_control(const char __user *arg1, const char *__user arg2, void *__user out_msg, int outlen)
{
    char name[KPM_NAME_LEN], args[KPM_ARGS_LEN];
    long namelen = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (namelen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return module_control0(name, arglen <= 0 ? 0 : args, out_msg, outlen);
}

static long call_kpm_unload(const char *__user arg1, void *__user reserved)
{
    char name[KPM_NAME_LEN];
    long len = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (len <= 0) return -EINVAL;
    return unload_module(name, reserved);
}

static long call_kpm_nums()
{
    return get_module_nums();
}

static long call_kpm_list(char *__user names, int len)
{
    if (len <= 0) return -EINVAL;
    char buf[4096];
    int sz = list_modules(buf, sizeof(buf));
    if (sz > len) return -ENOBUFS;
    sz = compat_copy_to_user(names, buf, len);
    return sz;
}

static long call_kpm_info(const char *__user uname, char *__user out_info, int out_len)
{
    if (out_len <= 0) return -EINVAL;
    char name[64];
    char buf[2048];
    int len = compat_strncpy_from_user(name, uname, sizeof(name));
    if (len <= 0) return -EINVAL;
    int sz = get_module_info(name, buf, sizeof(buf));
    if (sz < 0) return sz;
    if (sz > out_len) return -ENOBUFS;
    sz = compat_copy_to_user(out_info, buf, sz);
    return sz;
}

static long call_su(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->scontext[sizeof(profile->scontext) - 1] = '\0';
    int rc = commit_su(profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_su_task(pid_t pid, struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->scontext[sizeof(profile->scontext) - 1] = '\0';
    int rc = task_su(pid, profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_skey_get(char *__user out_key, int out_len)
{
    const char *key = get_superkey();
    int klen = strlen(key);
    if (klen >= out_len) return -ENOMEM;
    int rc = compat_copy_to_user(out_key, get_superkey(), klen + 1);
    return rc;
}

static long call_skey_set(char *__user new_key)
{
    char buf[SUPER_KEY_LEN];
    int len = compat_strncpy_from_user(buf, new_key, sizeof(buf));
    if (len >= SUPER_KEY_LEN && buf[SUPER_KEY_LEN - 1]) return -E2BIG;
    reset_superkey(new_key);
    return 0;
}

static long call_skey_root_enable(int enable)
{
    enable_auth_root_key(enable);
    return 0;
}

static unsigned long call_pid_virt_to_phys(pid_t pid, uintptr_t vaddr)
{
    return pid_virt_to_phys(pid, vaddr);
}

static long call_grant_uid(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    int rc = su_add_allow_uid(profile->uid, profile->to_uid, profile->scontext, 1);
    kvfree(profile);
    return rc;
}

static long call_revoke_uid(uid_t uid)
{
    return su_remove_allow_uid(uid, 1);
}

static long call_su_allow_uid_nums()
{
    return su_allow_uid_nums();
}

static long call_su_list_allow_uid(uid_t *__user uids, int num)
{
    return su_allow_uids(1, uids, num);
}

static long call_su_allow_uid_profile(uid_t uid, struct su_profile *__user uprofile)
{
    return su_allow_uid_profile(1, uid, uprofile);
}

static long call_reset_su_path(const char *__user upath)
{
    return su_reset_path(strndup_user(upath, SU_PATH_MAX_LEN));
}

static long call_su_get_path(char *__user ubuf, int buf_len)
{
    const char *path = su_get_path();
    int len = strlen(path);
    if (buf_len <= len) return -ENOBUFS;
    return compat_copy_to_user(ubuf, path, len + 1);
}

static long call_su_get_allow_sctx(char *__user usctx, int ulen)
{
    int len = strlen(all_allow_sctx);
    if (ulen <= len) return -ENOBUFS;
    return compat_copy_to_user(usctx, all_allow_sctx, len + 1);
}

static long call_su_set_allow_sctx(char *__user usctx)
{
    char buf[SUPERCALL_SCONTEXT_LEN];
    buf[0] = '\0';
    int len = compat_strncpy_from_user(buf, usctx, sizeof(buf));
    if (len >= SUPERCALL_SCONTEXT_LEN && buf[SUPERCALL_SCONTEXT_LEN - 1]) return -E2BIG;
    return set_all_allow_sctx(buf);
}

static long supercall(int is_key_auth, long cmd, long arg1, long arg2, long arg3, long arg4)
{
    switch (cmd) {
    case SUPERCALL_HELLO:
        logki(SUPERCALL_HELLO_ECHO "\n");
        return SUPERCALL_HELLO_MAGIC;
    case SUPERCALL_KLOG:
        return call_klog((const char *__user)arg1);
    case SUPERCALL_KERNELPATCH_VER:
        return kpver;
    case SUPERCALL_KERNEL_VER:
        return kver;
    }

    switch (cmd) {
    case SUPERCALL_SU:
        return call_su((struct su_profile * __user) arg1);
    case SUPERCALL_SU_TASK:
        return call_su_task((pid_t)arg1, (struct su_profile * __user) arg2);

    case SUPERCALL_SU_GRANT_UID:
        return call_grant_uid((struct su_profile * __user) arg1);
    case SUPERCALL_SU_REVOKE_UID:
        return call_revoke_uid((uid_t)arg1);
    case SUPERCALL_SU_NUMS:
        return call_su_allow_uid_nums();
    case SUPERCALL_SU_LIST:
        return call_su_list_allow_uid((uid_t *)arg1, (int)arg2);
    case SUPERCALL_SU_PROFILE:
        return call_su_allow_uid_profile((uid_t)arg1, (struct su_profile * __user) arg2);
    case SUPERCALL_SU_RESET_PATH:
        return call_reset_su_path((const char *)arg1);
    case SUPERCALL_SU_GET_PATH:
        return call_su_get_path((char *__user)arg1, (int)arg2);
    case SUPERCALL_SU_GET_ALLOW_SCTX:
        return call_su_get_allow_sctx((char *__user)arg1, (int)arg2);
    case SUPERCALL_SU_SET_ALLOW_SCTX:
        return call_su_set_allow_sctx((char *__user)arg1);
    default:
        break;
    }

    switch (cmd) {
    case SUPERCALL_BOOTLOG:
        return call_bootlog();
    case SUPERCALL_PANIC:
        return call_panic();
    case SUPERCALL_TEST:
        return call_test(arg1, arg2, arg3);
    default:
        break;
    }

    if (!is_key_auth) return -EPERM;

    switch (cmd) {
    case SUPERCALL_SKEY_GET:
        return call_skey_get((char *__user)arg1, (int)arg2);
    case SUPERCALL_SKEY_SET:
        return call_skey_set((char *__user)arg1);
    case SUPERCALL_SKEY_ROOT_ENABLE:
        return call_skey_root_enable((int)arg1);
        break;
    }

    switch (cmd) {
    case SUPERCALL_KPM_LOAD:
        return call_kpm_load((const char *__user)arg1, (const char *__user)arg2, (void *__user)arg3);
    case SUPERCALL_KPM_UNLOAD:
        return call_kpm_unload((const char *__user)arg1, (void *__user)arg2);
    case SUPERCALL_KPM_CONTROL:
        return call_kpm_control((const char *__user)arg1, (const char *__user)arg2, (char *__user)arg3, (int)arg4);
    case SUPERCALL_KPM_NUMS:
        return call_kpm_nums();
    case SUPERCALL_KPM_LIST:
        return call_kpm_list((char *__user)arg1, (int)arg2);
    case SUPERCALL_KPM_INFO:
        return call_kpm_info((const char *__user)arg1, (char *__user)arg2, (int)arg3);
    }

    switch (cmd) {
    case SUPERCALL_MEM_PHYS:
        return call_pid_virt_to_phys((pid_t)arg1, (uintptr_t)arg2);
    default:
        break;
    }

    return -ENOSYS;
}

static void before(hook_fargs6_t *args, void *udata)
{
    const char *__user ukey = (const char *__user)syscall_argn(args, 0);
    long ver_xx_cmd = (long)syscall_argn(args, 1);

    // todo: from 0.10.5
    // uint32_t ver = (ver_xx_cmd & 0xFFFFFFFF00000000ul) >> 32;
    // long xx = (ver_xx_cmd & 0xFFFF0000) >> 16;

    long cmd = ver_xx_cmd & 0xFFFF;
    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return;

    char key[MAX_KEY_LEN];
    long len = compat_strncpy_from_user(key, ukey, MAX_KEY_LEN);
    if (len <= 0) return;

    int is_key_auth = 0;

    if (!auth_superkey(key)) {
        is_key_auth = 1;
    } else if (!strcmp("su", key)) {
        uid_t uid = current_uid();
        if (!is_su_allow_uid(uid)) return;
    } else {
        return;
    }

    long a1 = (long)syscall_argn(args, 2);
    long a2 = (long)syscall_argn(args, 3);
    long a3 = (long)syscall_argn(args, 4);
    long a4 = (long)syscall_argn(args, 5);

    args->skip_origin = 1;
    args->ret = supercall(is_key_auth, cmd, a1, a2, a3, a4);
}

int supercall_install()
{
    int rc = 0;

    hook_err_t err = hook_syscalln(__NR_supercall, 6, before, 0, 0);
    if (err) {
        log_boot("install supercall hook error: %d\n", err);
        rc = err;
        goto out;
    }
out:
    return rc;
}
