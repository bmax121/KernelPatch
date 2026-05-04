/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

/*
 * Anti-sidechannel G5+G7:
 * G5: Replace fstatat/faccessat hook_syscalln with fp_hook + uid precheck.
 *     Hunter/FingerprintCheck UIDs not in allow-list → fast tail-call to original.
 * G7: Replace execve hook_syscalln with fp_hook + callback registry for KPMs.
 *     KPMs (IO_Redirect) call register_execve_before_hook() instead of hook_syscalln.
 *     All execve logic runs in one call stack without transit-framework overhead.
 */
#define ANTI_SIDECHANNEL_V4G

#include <linux/list.h>
#include <ktypes.h>
#include <compiler.h>
#include <stdbool.h>
#include <linux/syscall.h>
#include <ksyms.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <taskob.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <syscall.h>
#include <predata.h>
#include <predata.h>
#include <kconfig.h>
#include <linux/vmalloc.h>
#include <sucompat.h>
#include <symbol.h>
#include <uapi/linux/limits.h>
#include <predata.h>
#include <kstorage.h>

const char sh_path[] = SH_PATH;
const char default_su_path[] = SU_PATH;

#ifdef ANDROID
const char legacy_su_path[] = LEGACY_SU_PATH;
const char apd_path[] = APD_PATH;
#endif

static const char *current_su_path = 0;

static int su_kstorage_gid = -1;
static int exclude_kstorage_gid = -1;

int is_su_allow_uid(uid_t uid)
{
    int rc = 0;
    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR_OR_NULL(ks) || ks->dlen <= 0) goto out;

    struct su_profile *profile = (struct su_profile *)ks->data;
    rc = profile->uid == uid;

out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(is_su_allow_uid);

int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext)
{
    if (!scontext) scontext = "";
    struct su_profile profile = {
        uid,
        to_uid,
    };
    memcpy(profile.scontext, scontext, SUPERCALL_SCONTEXT_LEN);
    int rc = write_kstorage(su_kstorage_gid, uid, &profile, 0, sizeof(struct su_profile), false);
    logkfd("uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, scontext, rc);
    return rc;
}
KP_EXPORT_SYMBOL(su_add_allow_uid);

int su_remove_allow_uid(uid_t uid)
{
    return remove_kstorage(su_kstorage_gid, uid);
}
KP_EXPORT_SYMBOL(su_remove_allow_uid);

int su_allow_uid_nums()
{
    return kstorage_group_size(su_kstorage_gid);
}
KP_EXPORT_SYMBOL(su_allow_uid_nums);

static int allow_uids_cb(struct kstorage *kstorage, void *udata)
{
    struct
    {
        int is_user;
        uid_t *out_uids;
        int idx;
        int out_num;
    } *up = (typeof(up))udata;

    if (up->idx >= up->out_num) {
        return -ENOBUFS;
    }

    struct su_profile *profile = (struct su_profile *)kstorage->data;

    if (up->is_user) {
        int cprc = compat_copy_to_user(up->out_uids + up->idx, &profile->uid, sizeof(uid_t));
        if (cprc <= 0) {
            logkfd("compat_copy_to_user error: %d", cprc);
            return cprc;
        }
    } else {
        up->out_uids[up->idx] = profile->uid;
    }

    up->idx++;

    return 0;
}

int su_allow_uids(int is_user, uid_t *out_uids, int out_num)
{
    struct
    {
        int iu;
        uid_t *up;
        int idx;
        int out_num;
    } udata = { is_user, out_uids, 0, out_num };

    on_each_kstorage_elem(su_kstorage_gid, allow_uids_cb, &udata);

    return udata.idx;
}
KP_EXPORT_SYMBOL(su_allow_uids);

int su_allow_uid_profile(int is_user, uid_t uid, struct su_profile *out_profile)
{
    int rc = 0;

    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR(ks)) {
        rc = -ENOENT;
        goto out;
    }
    struct su_profile *profile = (struct su_profile *)ks->data;

    if (is_user) {
        rc = compat_copy_to_user(out_profile, profile, sizeof(struct su_profile));
        if (rc <= 0) {
            logkfd("compat_copy_to_user error: %d", rc);
            goto out;
        }
    } else {
        memcpy(out_profile, profile, sizeof(struct su_profile));
    }

out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(su_allow_uid_profile);

// no free, no lock
int su_reset_path(const char *path)
{
    if (!path) return -EINVAL;
    if (IS_ERR(path)) return PTR_ERR(path);
    current_su_path = path;
    logkfd("%s\n", current_su_path);
    dsb(ish);
    return 0;
}
KP_EXPORT_SYMBOL(su_reset_path);

const char *su_get_path()
{
    if (!current_su_path) current_su_path = default_su_path;
    return current_su_path;
}
KP_EXPORT_SYMBOL(su_get_path);

static void handle_before_execve(char **__user u_filename_p, char **__user uargv, void *udata)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) return;

    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        uid_t uid = current_uid();
        struct su_profile profile;
        if (su_allow_uid_profile(0, uid, &profile)) return;

        uid_t to_uid = profile.to_uid;
        const char *sctx = profile.scontext;
        commit_su(to_uid, sctx);

#ifdef ANDROID
        struct file *filp = filp_open(apd_path, O_RDONLY, 0);
        if (!filp || IS_ERR(filp)) {
#endif
            void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
            if (uptr && !IS_ERR(uptr)) {
                *u_filename_p = (char *__user)uptr;
            }
            logkfi("call su uid: %d, to_uid: %d, sctx: %s, uptr: %llx\n", uid, to_uid, sctx, uptr);
#ifdef ANDROID
        } else {
            filp_close(filp, 0);

            // command
            uint64_t sp = 0;
            sp = current_user_stack_pointer();
            sp -= sizeof(apd_path);
            sp &= 0xFFFFFFFFFFFFFFF8;
            int cplen = compat_copy_to_user((void *)sp, apd_path, sizeof(apd_path));
            if (cplen > 0) {
                *u_filename_p = (char *)sp;
            }

            // argv
            int argv_cplen = 0;
            if (strcmp(legacy_su_path, filename)) {
                if (argv_cplen <= 0) {
                    sp = sp ?: current_user_stack_pointer();
                    sp -= sizeof(legacy_su_path);
                    sp &= 0xFFFFFFFFFFFFFFF8;
                    argv_cplen = compat_copy_to_user((void *)sp, legacy_su_path, sizeof(legacy_su_path));
                    if (argv_cplen > 0) {
                        int rc = set_user_arg_ptr(0, *uargv, 0, sp);
                        if (rc < 0) { // todo: modify entire argv
                            logkfi("call apd argv error, uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, sctx,
                                   rc);
                        }
                    }
                }
            }
            logkfi("call apd uid: %d, to_uid: %d, sctx: %s, cplen: %d, %d\n", uid, to_uid, sctx, cplen, argv_cplen);
        }
#endif // ANDROID
    } else if (!strcmp(SUPERCMD, filename)) {
        void handle_supercmd(char **__user u_filename_p, char **__user uargv);
        handle_supercmd(u_filename_p, uargv);
        return;
    }
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2107
// COMPAT_SYSCALL_DEFINE3(execve, const char __user *, filename,
// 	const compat_uptr_t __user *, argv,
// 	const compat_uptr_t __user *, envp)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2087
// SYSCALL_DEFINE3(execve, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp)

static void before_execve(hook_fargs3_t *args, void *udata)
{
    void *arg0p = syscall_argn_p(args, 0);
    void *arg1p = syscall_argn_p(args, 1);
    handle_before_execve((char **)arg0p, (char **)arg1p, udata);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2114
// COMPAT_SYSCALL_DEFINE5(execveat, int, fd,
// 		       const char __user *, filename,
// 		       const compat_uptr_t __user *, argv,
// 		       const compat_uptr_t __user *, envp,
// 		       int,  flags)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2095
// SYSCALL_DEFINE5(execveat, int, fd, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp, int, flags)
__maybe_unused static void before_execveat(hook_fargs5_t *args, void *udata)
{
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    handle_before_execve((char **)arg1p, (char **)arg2p, udata);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/stat.c#L431
// SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
// 		struct stat __user *, statbuf, int, flag)

// https://elixir.bootlin.com/linux/v6.1/source/fs/open.c#L492
// SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)

// https://elixir.bootlin.com/linux/v6.1/source/fs/open.c#L497
// SYSCALL_DEFINE4(faccessat2, int, dfd, const char __user *, filename, int, mode, int, flags)

// https://elixir.bootlin.com/linux/v6.1/source/fs/stat.c#L661
// SYSCALL_DEFINE5(statx,
// 		int, dfd, const char __user *, filename, unsigned, flags,
// 		unsigned int, mask,
// 		struct statx __user *, buffer)
static void su_handler_arg1_ufilename_before(hook_fargs6_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) return;

    char __user **u_filename_p = (char __user **)syscall_argn_p(args, 1);

    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, *u_filename_p, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
        if (uptr && !IS_ERR(uptr)) {
            *u_filename_p = uptr;
        } else {
            logkfi("su uid: %d, cp stack error: %d\n", uid, uptr);
        }
    }
}

int set_ap_mod_exclude(uid_t uid, int exclude)
{
    int rc = 0;
    if (exclude) {
        rc = write_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    } else {
        rc = remove_kstorage(exclude_kstorage_gid, uid);
    }
    return rc;
}
KP_EXPORT_SYMBOL(set_ap_mod_exclude);

int get_ap_mod_exclude(uid_t uid)
{
    int exclude = 0;
    int rc = read_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    if (rc < 0) return 0;
    return exclude;
}
KP_EXPORT_SYMBOL(get_ap_mod_exclude);

int list_ap_mod_exclude(uid_t *uids, int len)
{
    long ids[len];
    int cnt = list_kstorage_ids(exclude_kstorage_gid, ids, len, false);
    for (int i = 0; i < len; i++) {
        uids[i] = (uid_t)ids[i];
    }
    return cnt;
}
KP_EXPORT_SYMBOL(list_ap_mod_exclude);

#ifdef ANTI_SIDECHANNEL_V4G
/* ====== Anti-sidechannel G5: fstatat/faccessat fp_hook + uid precheck ====== */
/* ====== Anti-sidechannel G7: execve fp_hook + KPM callback registry   ====== */

/* Saved original function pointers (set by fp_hook at install time) */
static uintptr_t g5_orig_fstatat         = 0;
static uintptr_t g5_orig_faccessat       = 0;
static uintptr_t g7_orig_execve          = 0;

/* ---- G7 KPM callback registry ---- */
#define EXECVE_HOOK_CB_MAX 4

typedef long (*execve_before_hook_fn_t)(const char __user *filename,
                                         const char __user *const __user *argv,
                                         void *udata);

static struct {
    execve_before_hook_fn_t fn;
    void *udata;
} g_execve_cbs[EXECVE_HOOK_CB_MAX];
static int g_execve_cb_count = 0;

/*
 * register_execve_before_hook - KPM API: register a callback invoked on every execve.
 *
 * The callback signature is:
 *   long cb(const char __user *filename,
 *           const char __user *const __user *argv, void *udata)
 *   Returns: 0 = allow, negative errno = block with that error.
 *
 * KPMs (e.g. IO_Redirect) should call this instead of hook_syscalln(__NR_execve, ...)
 * to avoid adding transit-framework overhead on top of sucompat's fp_hook wrapper.
 *
 * Exported via KP_EXPORT_SYMBOL so KPMs can find it with kallsyms_lookup_name().
 */
int register_execve_before_hook(execve_before_hook_fn_t fn, void *udata)
{
    if (!fn) return -EINVAL;
    if (g_execve_cb_count >= EXECVE_HOOK_CB_MAX) return -ENOMEM;
    /* Avoid duplicates */
    for (int i = 0; i < g_execve_cb_count; i++) {
        if (g_execve_cbs[i].fn == fn) return 0;
    }
    g_execve_cbs[g_execve_cb_count].fn    = fn;
    g_execve_cbs[g_execve_cb_count].udata = udata;
    g_execve_cb_count++;
    return 0;
}
KP_EXPORT_SYMBOL(register_execve_before_hook);

void unregister_execve_before_hook(execve_before_hook_fn_t fn)
{
    for (int i = 0; i < g_execve_cb_count; i++) {
        if (g_execve_cbs[i].fn == fn) {
            /* Shift remaining entries down */
            for (int j = i; j < g_execve_cb_count - 1; j++)
                g_execve_cbs[j] = g_execve_cbs[j + 1];
            g_execve_cb_count--;
            return;
        }
    }
}
KP_EXPORT_SYMBOL(unregister_execve_before_hook);

/*
 * G5: fstatat fp_hook wrapper with uid precheck.
 *
 * Called as (wrapper mode): sys_fstatat(struct pt_regs *regs)
 *   x0 = regs, regs->regs[1] = filename (arg1)
 * Called as (nowrap  mode): sys_fstatat(long dfd, const char __user *filename, ...)
 *   x0 = dfd, x1 = filename
 *
 * Fast path: uid not in su allow list → tail-call to original, zero overhead.
 * Slow path: uid in allow list → do su-path filename substitution.
 */
static long sucompat_fstatat_g5(long arg0, long arg1, long arg2, long arg3)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) {
        /* Fast path */
        if (has_syscall_wrapper)
            return ((long (*)(struct pt_regs *))g5_orig_fstatat)((struct pt_regs *)arg0);
        return ((long (*)(long, long, long, long))g5_orig_fstatat)(arg0, arg1, arg2, arg3);
    }

    /* Slow path: check and possibly substitute su path in filename */
    char __user **u_filename_p;
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        u_filename_p = (char __user **)&regs->regs[1];
    } else {
        u_filename_p = (char __user **)&arg1;
    }

    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, *u_filename_p, sizeof(filename));
    if (flen > 0 && !strcmp(current_su_path, filename)) {
        void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
        if (uptr && !IS_ERR(uptr))
            *u_filename_p = (char __user *)uptr;
    }

    if (has_syscall_wrapper)
        return ((long (*)(struct pt_regs *))g5_orig_fstatat)((struct pt_regs *)arg0);
    return ((long (*)(long, long, long, long))g5_orig_fstatat)(arg0, arg1, arg2, arg3);
}

/*
 * G5: faccessat fp_hook wrapper with uid precheck.
 *
 * Called as (wrapper mode): sys_faccessat(struct pt_regs *regs)
 *   x0 = regs, regs->regs[1] = filename (arg1)
 * Called as (nowrap  mode): sys_faccessat(long dfd, const char __user *filename, int mode)
 *   x0 = dfd, x1 = filename, x2 = mode
 */
static long sucompat_faccessat_g5(long arg0, long arg1, long arg2)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) {
        /* Fast path */
        if (has_syscall_wrapper)
            return ((long (*)(struct pt_regs *))g5_orig_faccessat)((struct pt_regs *)arg0);
        return ((long (*)(long, long, long))g5_orig_faccessat)(arg0, arg1, arg2);
    }

    /* Slow path */
    char __user **u_filename_p;
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        u_filename_p = (char __user **)&regs->regs[1];
    } else {
        u_filename_p = (char __user **)&arg1;
    }

    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, *u_filename_p, sizeof(filename));
    if (flen > 0 && !strcmp(current_su_path, filename)) {
        void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
        if (uptr && !IS_ERR(uptr))
            *u_filename_p = (char __user *)uptr;
    }

    if (has_syscall_wrapper)
        return ((long (*)(struct pt_regs *))g5_orig_faccessat)((struct pt_regs *)arg0);
    return ((long (*)(long, long, long))g5_orig_faccessat)(arg0, arg1, arg2);
}

/*
 * G7: execve fp_hook wrapper.
 *
 * Calls handle_before_execve (sucompat's own su-path substitution / apd dispatch),
 * then calls all registered KPM callbacks (e.g. IO_Redirect's execve blocking).
 * If any callback returns a negative errno, the execve is blocked with that error.
 *
 * Called as (wrapper mode): sys_execve(struct pt_regs *regs)
 *   x0 = regs, regs->regs[0]=filename, regs->regs[1]=argv, regs->regs[2]=envp
 * Called as (nowrap  mode): sys_execve(const char __user *filename, ...)
 *   x0 = filename, x1 = argv, x2 = envp
 *
 * Note: NO uid precheck here — APatch Manager (uid=10247) needs handle_before_execve
 * to intercept /system/bin/cu (SUPERCMD) even before its uid is in the allow list.
 */
static long sucompat_execve_g7(long arg0, long arg1, long arg2)
{
    char __user **u_filename_p;
    char __user **u_argv_p;

    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        u_filename_p = (char __user **)&regs->regs[0];
        u_argv_p     = (char __user **)&regs->regs[1];
    } else {
        u_filename_p = (char __user **)&arg0;
        u_argv_p     = (char __user **)&arg1;
    }

    /* sucompat built-in: su-path substitution, apd dispatch, commit_su */
    handle_before_execve(u_filename_p, u_argv_p, (void *)0);

    /* Call registered KPM callbacks */
    for (int i = 0; i < g_execve_cb_count; i++) {
        long ret = g_execve_cbs[i].fn(
            (const char __user *)*u_filename_p,
            (const char __user *const __user *)*u_argv_p,
            g_execve_cbs[i].udata);
        if (ret < 0)
            return ret; /* blocked by KPM callback */
    }

    /* Call original execve */
    if (has_syscall_wrapper)
        return ((long (*)(struct pt_regs *))g7_orig_execve)((struct pt_regs *)arg0);
    return ((long (*)(long, long, long))g7_orig_execve)(arg0, arg1, arg2);
}

#endif /* ANTI_SIDECHANNEL_V4G */

int su_compat_init()
{
    current_su_path = default_su_path;

    su_kstorage_gid = try_alloc_kstroage_group();
    if (su_kstorage_gid != KSTORAGE_SU_LIST_GROUP) return -ENOMEM;

    exclude_kstorage_gid = try_alloc_kstroage_group();
    if (exclude_kstorage_gid != KSTORAGE_EXCLUDE_LIST_GROUP) return -ENOMEM;

#ifdef ANDROID
    // default shell
    if (!all_allow_sctx[0]) {
        strcpy(all_allow_sctx, ALL_ALLOW_SCONTEXT_MAGISK);
    }
    su_add_allow_uid(2000, 0, all_allow_sctx);
    su_add_allow_uid(0, 0, all_allow_sctx);
#endif

    hook_err_t rc = HOOK_NO_ERR;

    uint8_t su_config = patch_config->patch_su_config;
    bool enable = !!(su_config & PATCH_CONFIG_SU_ENABLE);
    bool wrap = !!(su_config & PATCH_CONFIG_SU_HOOK_NO_WRAP);
    log_boot("su config: %x, enable: %d, wrap: %d\n", su_config, enable, wrap);

    // if (!enable) return;

#ifdef ANTI_SIDECHANNEL_V4G
    /* G7: execve — fp_hook (no transit framework overhead) */
    if (sys_call_table) {
        fp_hook((uintptr_t)(sys_call_table + __NR_execve),
                (void *)sucompat_execve_g7,
                (void **)&g7_orig_execve);
        log_boot("sucompat G7: fp_hook execve orig=%llx\n",
                 (unsigned long long)g7_orig_execve);
    } else {
        rc = hook_syscalln(__NR_execve, 3, before_execve, 0, (void *)0);
        log_boot("sucompat G7 fallback: hook_syscalln execve rc=%d\n", rc);
    }

    /* G5: fstatat — fp_hook + uid precheck */
    if (sys_call_table) {
        fp_hook((uintptr_t)(sys_call_table + __NR3264_fstatat),
                (void *)sucompat_fstatat_g5,
                (void **)&g5_orig_fstatat);
        log_boot("sucompat G5: fp_hook fstatat orig=%llx\n",
                 (unsigned long long)g5_orig_fstatat);
    } else {
        rc = hook_syscalln(__NR3264_fstatat, 4, su_handler_arg1_ufilename_before, 0, (void *)0);
        log_boot("sucompat G5 fallback: hook_syscalln fstatat rc=%d\n", rc);
    }

    /* G5: faccessat — fp_hook + uid precheck */
    if (sys_call_table) {
        fp_hook((uintptr_t)(sys_call_table + __NR_faccessat),
                (void *)sucompat_faccessat_g5,
                (void **)&g5_orig_faccessat);
        log_boot("sucompat G5: fp_hook faccessat orig=%llx\n",
                 (unsigned long long)g5_orig_faccessat);
    } else {
        rc = hook_syscalln(__NR_faccessat, 3, su_handler_arg1_ufilename_before, 0, (void *)0);
        log_boot("sucompat G5 fallback: hook_syscalln faccessat rc=%d\n", rc);
    }

    /* Compat syscalls: keep using hook_compat_syscalln (32-bit apps not perf-critical) */
    rc = hook_compat_syscalln(11, 3, before_execve, 0, (void *)1);
    log_boot("hook 32 __NR_execve rc: %d\n", rc);

    rc = hook_compat_syscalln(327, 4, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook 32 __NR_fstatat64 rc: %d\n", rc);

    rc = hook_compat_syscalln(334, 3, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook 32 __NR_faccessat rc: %d\n", rc);

#else /* !ANTI_SIDECHANNEL_V4G: original transit-framework hooks */
    rc = hook_syscalln(__NR_execve, 3, before_execve, 0, (void *)0);
    log_boot("hook __NR_execve rc: %d\n", rc);

    rc = hook_syscalln(__NR3264_fstatat, 4, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook __NR3264_fstatat rc: %d\n", rc);

    rc = hook_syscalln(__NR_faccessat, 3, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook __NR_faccessat rc: %d\n", rc);

    // __NR_execve 11
    rc = hook_compat_syscalln(11, 3, before_execve, 0, (void *)1);
    log_boot("hook 32 __NR_execve rc: %d\n", rc);

    // __NR_fstatat64 327
    rc = hook_compat_syscalln(327, 4, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook 32 __NR_fstatat64 rc: %d\n", rc);

    //  __NR_faccessat 334
    rc = hook_compat_syscalln(334, 3, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook 32 __NR_faccessat rc: %d\n", rc);
#endif /* ANTI_SIDECHANNEL_V4G */

    return 0;
}