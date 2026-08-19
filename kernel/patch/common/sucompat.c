/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

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
#include <userd.h>
#include <symbol.h>
#include <kallsyms.h>
#include <uapi/linux/limits.h>
#include <predata.h>
#include <kstorage.h>
#include <selinux_hide.h>

const char sh_path[] = SH_PATH;
const char default_su_path[] = SU_PATH;

#ifdef ANDROID
const char legacy_su_path[] = LEGACY_SU_PATH;
const char apd_path[] = APD_PATH;
extern int android_is_safe_mode;
#endif
const char sucompat_file[] = "/data/adb/ap/sucompat";
static const char *current_su_path = 0;

static int su_kstorage_gid = -1;
static int exclude_kstorage_gid = -1;
static void su_register_path_probe_hooks(void);
static void su_unregister_path_probe_hooks(void);
long kp_control_feature_sc(const char __user *uname, int state)
{
    char name[64];
    int len = compat_strncpy_from_user(name, uname, sizeof(name));
    if (len <= 0)
        return -EINVAL;

    if (!strcmp(name, "selinux_hide")) {
        return selinux_hide_control(state);
    }

    if (!strcmp(name, "sucompat_extra") || !strcmp(name, "path_probe")) {
        if (state < 0)
            /* Query: check if the hooks are currently registered. */
            return 0;   /* not tracked */
        if (state)
            su_register_path_probe_hooks();
        else
            su_unregister_path_probe_hooks();
        logkfi("sucompat_extra %s via supercall\n",
               state ? "enabled" : "disabled");
        return 0;
    }

    /* Unknown feature name. */
    return -ENOENT;
}
KP_EXPORT_SYMBOL(kp_control_feature_sc);

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
    if (!is_su_allow_uid(uid) && !is_trusted_manager_uid(uid)) return;

    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

#ifdef ANDROID
    // Match the configured su path (default /system/bin/kp) and the legacy
    // /system/bin/su that shells and detectors also exec. execve does not go
    // through getname_flags, so this before-hook is the only place to redirect
    // a real exec of /system/bin/su to sh/apd.
    if (strcmp(filename, current_su_path) && strcmp(filename, legacy_su_path)) {
        if (!strcmp(SUPERCMD, filename)) {
            void handle_supercmd(char **__user u_filename_p, char **__user uargv);
            handle_supercmd(u_filename_p, uargv);
        }
        return;
    }
#else
    if (strcmp(filename, current_su_path)) {
        if (!strcmp(SUPERCMD, filename)) {
            void handle_supercmd(char **__user u_filename_p, char **__user uargv);
            handle_supercmd(u_filename_p, uargv);
        }
        return;
    }
#endif
    {
        uid_t uid = current_uid();
        struct su_profile profile = { .to_uid = 0 };
        if (is_trusted_manager_uid(uid)) {
            strncpy(profile.scontext, all_allow_sctx, sizeof(profile.scontext) - 1);
            profile.scontext[sizeof(profile.scontext) - 1] = '\0';
        } else if (su_allow_uid_profile(0, uid, &profile)) {
            return;
        }

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
__maybe_unused static void su_handler_arg1_ufilename_before(hook_fargs6_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid) && !is_trusted_manager_uid(uid)) return;

    char __user **u_filename_p = (char __user **)syscall_argn_p(args, 1);

    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, *u_filename_p, sizeof(filename));
    if (flen <= 0) return;

#ifdef ANDROID
    if (strcmp(filename, current_su_path) && strcmp(filename, legacy_su_path)) return;
#else
    if (strcmp(filename, current_su_path)) return;
#endif
    {
        void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
        if (uptr && !IS_ERR(uptr)) {
            *u_filename_p = uptr;
        } else {
            logkfi("su uid: %d, cp stack error: %d\n", uid, uptr);
        }
    }
}

static void after_getname_flags(hook_fargs3_t *args, void *udata)
{
    struct filename *fn = (struct filename *)args->ret;
    if (IS_ERR_OR_NULL(fn)) return;

    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid) && !is_trusted_manager_uid(uid)) return;

    const char *name = fn->name;
    if (!name || strcmp(name, su_get_path())) return;

    if (strlen(sh_path) <= strlen(name)) {
        strcpy((char *)name, sh_path);
        return;
    }

    if (kfunc(getname_kernel) && kfunc(putname)) {
        struct filename *nf = kfunc(getname_kernel)(sh_path);
        if (!IS_ERR_OR_NULL(nf)) {
            kfunc(putname)(fn);
            args->ret = (uint64_t)nf;
            return;
        }
    }

    logkfi("uid: %d, cannot redirect su path to %s\n", uid, sh_path);
}

// stat-class probes on a real third-party su binary: security_inode_getattr fires
// because the file genuinely exists. Show it only to granted uids (return 0, same
// as the virtual su path which getname_flags redirects to sh for them) and hide
// it from everyone else by failing the getattr (-ENOENT), which makes vfs_getattr
// report ENOENT and the probe sees no su. struct path is { mnt; dentry; }.
typedef char *(*su_dentry_path_raw_t)(void *dentry, char *buf, int buflen);
static su_dentry_path_raw_t su_dentry_path_raw = 0;

static void after_security_inode_getattr(hook_fargs1_t *args, void *udata)
{
    if ((long)args->ret < 0) return; // already an error, nothing to do

    uid_t uid = current_uid();
    bool granted = is_su_allow_uid(uid) || is_trusted_manager_uid(uid);

    void *path = (void *)args->arg0;
    if (!path) return;
    void *dentry = *(void **)((char *)path + 8); // path->dentry
    if (!dentry || !su_dentry_path_raw) return;

    char buf[PATH_MAX];
    char *p = su_dentry_path_raw(dentry, buf, sizeof(buf));
    if (!p || !p[0]) return;

#ifdef ANDROID
    if (strcmp(p, su_get_path()) && strcmp(p, legacy_su_path)) return;
#else
    if (strcmp(p, su_get_path())) return;
#endif

    // Hide the real su file from unprivileged callers; keep it visible to granted ones.
    if (!granted) {
        args->ret = (uint64_t)-ENOENT;
        logkfi("uid: %d, hide real su file: %s\n", uid, p);
    } else {
        logkfi("uid: %d, show real su file: %s\n", uid, p);
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

    rc = hook_syscalln(__NR_execve, 3, before_execve, 0, (void *)0);
    log_boot("hook __NR_execve rc: %d\n", rc);

    /* Android init may execute commands through execveat().  Keep the
     * SUPERCMD/su redirection on both entry points; otherwise /system/bin/
     * truncate is executed literally and every apd bootstrap command exits
     * with status 1. */
    rc = hook_syscalln(__NR_execveat, 5, before_execveat, 0, (void *)0);
    log_boot("hook __NR_execveat rc: %d\n", rc);

    // __NR_execve 11
    rc = hook_compat_syscalln(11, 3, before_execve, 0, (void *)1);
    log_boot("hook 32 __NR_execve rc: %d\n", rc);

    // __NR_execveat 387 on arm64 compat
    rc = hook_compat_syscalln(387, 5, before_execveat, 0, (void *)1);
    log_boot("hook 32 __NR_execveat rc: %d\n", rc);

    // Redirect the su path only for granted uids: after_getname_flags checks
    // is_su_allow_uid/is_trusted_manager_uid, so a granted app's stat/access on
    // /system/bin/su or /system/bin/kp lands on the real /system/bin/sh and the
    // probe reports it present, while unprivileged callers keep the virtual su
    // path un-redirected and get ENOENT (hidden).
    //
    // LTO kernels (e.g. OPPO 6.1) emit getname_flags as a CFI wrapper with zero
    // callers; the real entry all path syscalls reach is __original_getname_flags.
    // Prefer it, fall back to getname_flags for non-LTO builds.
    unsigned long getname_flags_addr = 0;
    getname_flags_addr = kallsyms_lookup_name("__original_getname_flags");
    if (!getname_flags_addr) {
        getname_flags_addr = kallsyms_lookup_name("getname_flags");
    }else{
        logkfi("found __original_getname_flags: %llx\n", getname_flags_addr);
    }
    if (getname_flags_addr) {
        rc = hook_wrap3((void *)getname_flags_addr, 0, after_getname_flags, (void *)0);
        log_boot("hook getname_flags rc: %d\n", rc);
    } else {
        log_boot("getname_flags not found\n");
    }


    return 0;
}

static void su_register_path_probe_hooks(void)
{
    #ifdef ANDROID
        if (unlikely(android_is_safe_mode)) return;
    #endif
    hook_err_t rc;

    rc = hook_syscalln(__NR3264_fstatat, 4, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook __NR3264_fstatat rc: %d\n", rc);

    rc = hook_syscalln(__NR_faccessat, 3, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook __NR_faccessat rc: %d\n", rc);

    /* 32-bit compat probes: fstatat64(327) / faccessat(334) */
    rc = hook_compat_syscalln(327, 4, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook 32 __NR_fstatat64 rc: %d\n", rc);

    rc = hook_compat_syscalln(334, 3, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook 32 __NR_faccessat rc: %d\n", rc);
}

static void su_unregister_path_probe_hooks(void)
{
    unhook_syscalln(__NR3264_fstatat, su_handler_arg1_ufilename_before, 0);
    unhook_syscalln(__NR_faccessat, su_handler_arg1_ufilename_before, 0);
    unhook_compat_syscalln(327, su_handler_arg1_ufilename_before, 0);
    unhook_compat_syscalln(334, su_handler_arg1_ufilename_before, 0);
}

void sucompat_init()
{
    struct file *file = filp_open(sucompat_file, O_RDONLY, 0);
    if (IS_ERR(file)) {
        log_boot("failed to open sucompat file: %ld\n", PTR_ERR(file));
        return;
    }
    filp_close(file, NULL);
    su_register_path_probe_hooks(); 
}
