/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

/*
 * Anti-sidechannel v4-G3: ARM64 ASM trampoline for syscall 45 (supercall).
 * Replace transit framework (hook_syscalln) with direct fp_hook + magic cookie check.
 * Hunter/FingerprintCheck test probes (bit[16:31] != 0x1158) hit fast path with zero
 * overhead (tail-call to original sys_truncate), making timing indistinguishable from
 * an unhoooked kernel.
 */
#define ANTI_SIDECHANNEL_V4G

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
#include <predata.h>
#include <linux/random.h>
#include <sucompat.h>
#include <accctl.h>
#include <kstorage.h>
#ifdef ANDROID
#include <userd.h>
#endif

#define MAX_KEY_LEN 128

#include <linux/umh.h>

static long call_test(long arg1, long arg2, long arg3)
{
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

static long call_buildtime(char __user *out_buildtime, int u_len)
{
    const char *buildtime = get_build_time();
    int len = strlen(buildtime);
    if (len >= u_len) return -ENOMEM;
    int rc = compat_copy_to_user(out_buildtime, buildtime, len + 1);
    return rc;
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
    int rc = compat_copy_to_user(out_key, key, klen + 1);
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

static long call_grant_uid(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    int rc = su_add_allow_uid(profile->uid, profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_revoke_uid(uid_t uid)
{
    return su_remove_allow_uid(uid);
}

static long call_su_allow_uid_nums()
{
    return su_allow_uid_nums();
}

#ifdef ANDROID
extern int android_is_safe_mode;
static long call_su_get_safemode()
{
    int result = android_is_safe_mode;
    logkfd("[call_su_get_safemode] %d\n", result);
    return result;
}

extern int load_ap_package_config(void);
static long call_ap_load_package_config()
{
    int result = load_ap_package_config();
    logkfd("[call_ap_load_package_config] loaded %d entries\n", result);
    return result;
}
#endif

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

static long call_kstorage_read(int gid, long did, void *out_data, int offset, int dlen)
{
    return read_kstorage(gid, did, out_data, offset, dlen, true);
}

static long call_kstorage_write(int gid, long did, void *data, int offset, int dlen)
{
    return write_kstorage(gid, did, data, offset, dlen, true);
}

static long call_list_kstorage_ids(int gid, long *ids, int ids_len)
{
    return list_kstorage_ids(gid, ids, ids_len, false);
}

static long call_kstorage_remove(int gid, long did)
{
    return remove_kstorage(gid, did);
}

static long supercall(int is_authed, long cmd, long arg1, long arg2, long arg3, long arg4)
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
    case SUPERCALL_BUILD_TIME:
        return call_buildtime((char *__user)arg1, (int)arg2);
    #ifdef ANDROID
    case SUPERCALL_AP_LOAD_PACKAGE_CONFIG:
        return call_ap_load_package_config();
    #endif
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

    case SUPERCALL_KSTORAGE_READ:
        return call_kstorage_read((int)arg1, (long)arg2, (void *)arg3, (int)((long)arg4 >> 32), (long)arg4 << 32 >> 32);
    case SUPERCALL_KSTORAGE_WRITE:
        return call_kstorage_write((int)arg1, (long)arg2, (void *)arg3, (int)((long)arg4 >> 32),
                                   (long)arg4 << 32 >> 32);
    case SUPERCALL_KSTORAGE_LIST_IDS:
        return call_list_kstorage_ids((int)arg1, (long *)arg2, (int)arg3);
    case SUPERCALL_KSTORAGE_REMOVE:
        return call_kstorage_remove((int)arg1, (long)arg2);

#ifdef ANDROID
    case SUPERCALL_SU_GET_SAFEMODE:
        return call_su_get_safemode();
#endif
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

    if (!is_authed) return -EPERM;

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
    default:
        break;
    }

    return -ENOSYS;
}

int is_trusted_manager_uid(uid_t uid)
{
    #ifdef ANDROID
    return is_trusted_manager_uid_android(uid);
    #endif
    return 0;
}

#ifndef ANTI_SIDECHANNEL_V4G
/* ====== Original transit-framework supercall install (G-series disabled) ====== */

static void before(hook_fargs6_t *args, void *udata)
{
    int uid = current_uid();
    if (get_ap_mod_exclude(uid)) return;

    int is_trusted_caller = 0;
    int is_authed = 0;
    if (has_preset_superkey()) {
        const char *__user key_user = (const char *__user)syscall_argn(args, 0);
        
        char key[MAX_KEY_LEN];
        long len = compat_strncpy_from_user(key, key_user, MAX_KEY_LEN);
        if (len <= 0) return;
        is_authed = !auth_superkey(key);
        is_trusted_caller = is_authed;
    }
    if (is_trusted_manager_uid(uid)) {
        is_trusted_caller = 1;
        is_authed = 1;
    } else if (is_su_allow_uid(uid)) {
        is_trusted_caller = 1;
    }

    if (!is_trusted_caller) return;

    long ver_xx_cmd = (long)syscall_argn(args, 1);
    long cmd = ver_xx_cmd & 0xFFFF;
    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return;

    // todo: from 0.10.5
    // uint32_t ver = (ver_xx_cmd & 0xFFFFFFFF00000000ul) >> 32;
    // long xx = (ver_xx_cmd & 0xFFFF0000) >> 16;

    long a1 = (long)syscall_argn(args, 2);
    long a2 = (long)syscall_argn(args, 3);
    long a3 = (long)syscall_argn(args, 4);
    long a4 = (long)syscall_argn(args, 5);

    args->skip_origin = 1;
    args->ret = supercall(is_authed, cmd, a1, a2, a3, a4);
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

#endif /* !ANTI_SIDECHANNEL_V4G */

#ifdef ANTI_SIDECHANNEL_V4G
/* ====== Anti-sidechannel G3: ARM64 ASM trampoline for syscall 45 ====== */

/*
 * Non-static globals so the assembly trampoline can access them via adrp.
 * MUST be non-static: the assembler uses PC-relative addressing (adrp + ldr :lo12:)
 * which is auto-relocated at kpimg load time — correct at runtime.
 *
 * DO NOT use a storage indirection: kpimg global initializers store compile-time
 * offsets, not runtime addresses. Double-indirection via a storage pointer causes
 * a kernel panic (see anti-sidechannel doc section 21.13 for the full analysis).
 */
uintptr_t g_orig_wrapper = 0;  /* original sys_truncate (wrapper mode) */
uintptr_t g_orig_nowrap  = 0;  /* original sys_truncate (nowrap mode) */
uintptr_t g_orig_compat  = 0;  /* original compat_sys_truncate */

/* Forward declarations for assembly-defined trampolines */
extern void supercall_trampoline_wrapper(void);
extern void supercall_trampoline_nowrap(void);
extern void supercall_trampoline_compat(void);

/*
 * Shared authentication + dispatch logic for the slow path.
 * Called only when bit[16:31] of ver_and_cmd == 0x1158 (real APatch supercall).
 */
static __always_inline long _supercall_dispatch(int uid,
                                                 const char *__user key_user,
                                                 long ver_and_cmd,
                                                 long a1, long a2, long a3, long a4)
{
    if (get_ap_mod_exclude(uid)) return -1; /* signal: call original */

    int is_trusted_caller = 0;
    int is_authed = 0;

    if (has_preset_superkey()) {
        char key[MAX_KEY_LEN];
        long len = compat_strncpy_from_user(key, key_user, MAX_KEY_LEN);
        if (len <= 0) return -1;
        is_authed = !auth_superkey(key);
        is_trusted_caller = is_authed;
    }
    if (is_trusted_manager_uid(uid)) {
        is_trusted_caller = 1;
        is_authed = 1;
    } else if (is_su_allow_uid(uid)) {
        is_trusted_caller = 1;
    }

    if (!is_trusted_caller) return -1;

    long cmd = ver_and_cmd & 0xFFFF;
    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return -1;

    return supercall(is_authed, cmd, a1, a2, a3, a4);
}

/*
 * supercall_g_slow_path_wrapper - C slow path for has_syscall_wrapper=1 kernels.
 * Called by supercall_trampoline_wrapper when the magic cookie matches.
 * Receives: x0 = pt_regs *
 */
long supercall_g_slow_path_wrapper(struct pt_regs *regs)
{
    int uid = current_uid();
    const char *__user key_user = (const char *__user)regs->regs[0];
    long ver_and_cmd = (long)regs->regs[1];
    long a1 = (long)regs->regs[2];
    long a2 = (long)regs->regs[3];
    long a3 = (long)regs->regs[4];
    long a4 = (long)regs->regs[5];

    long ret = _supercall_dispatch(uid, key_user, ver_and_cmd, a1, a2, a3, a4);
    if (ret == -1)
        return ((long (*)(struct pt_regs *))g_orig_wrapper)(regs);
    return ret;
}

/*
 * supercall_g_slow_path_nowrap - C slow path for has_syscall_wrapper=0 kernels.
 * Called by supercall_trampoline_nowrap when the magic cookie matches.
 * Receives direct syscall args in registers x0..x5.
 */
long supercall_g_slow_path_nowrap(long arg0, long arg1, long arg2,
                                   long arg3, long arg4, long arg5)
{
    int uid = current_uid();
    const char *__user key_user = (const char *__user)arg0;
    long ver_and_cmd = arg1;

    long ret = _supercall_dispatch(uid, key_user, ver_and_cmd,
                                   arg2, arg3, arg4, arg5);
    if (ret == -1)
        return ((long (*)(long, long, long, long, long, long))g_orig_nowrap)(
            arg0, arg1, arg2, arg3, arg4, arg5);
    return ret;
}

int supercall_install()
{
    if (!sys_call_table) {
        log_boot("supercall: sys_call_table not found, G3 install failed\n");
        return -EINVAL;
    }

    void *trampoline;
    uintptr_t *orig_ptr;

    if (has_syscall_wrapper) {
        trampoline = (void *)supercall_trampoline_wrapper;
        orig_ptr   = &g_orig_wrapper;
    } else {
        trampoline = (void *)supercall_trampoline_nowrap;
        orig_ptr   = &g_orig_nowrap;
    }

    fp_hook((uintptr_t)(sys_call_table + __NR_supercall), trampoline, (void **)orig_ptr);
    log_boot("supercall: anti-sidechannel v4-G3 (%s mode) installed, orig=%llx\n",
             has_syscall_wrapper ? "wrapper" : "nowrap", (unsigned long long)*orig_ptr);

    if (compat_sys_call_table) {
        fp_hook((uintptr_t)(compat_sys_call_table + __NR_supercall),
                (void *)supercall_trampoline_compat,
                (void **)&g_orig_compat);
        log_boot("supercall: G3 compat trampoline installed, orig=%llx\n",
                 (unsigned long long)g_orig_compat);
    }

    return 0;
}

#endif /* ANTI_SIDECHANNEL_V4G */
