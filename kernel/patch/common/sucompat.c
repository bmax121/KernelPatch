/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <linux/list.h>
#include <ktypes.h>
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
#include <linux/uaccess.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <taskob.h>
#include <linux/ptrace.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <syscall.h>
#include <predata.h>
#include <uapi/scdefs.h>
#include <predata.h>
#include <kconfig.h>
#include <linux/vmalloc.h>
#include <sucompat.h>
#include <symbol.h>
#include <uapi/linux/limits.h>

#ifdef ANDROID
const char sh_path[] = ANDROID_SH_PATH;
const char default_su_path[] = ANDROID_SU_PATH;
const char legacy_su_path[] = ANDROID_LEGACY_SU_PATH;
const char apd_path[] = APD_PATH;
#else
const char sh_path[] = LINUX_SH_PATH;
const char default_su_path[] = LINUX_SU_PATH;
#endif

static const char *current_su_path = 0;

static struct list_head allow_uid_list;
static spinlock_t list_lock;

static void allow_reclaim_callback(struct rcu_head *rcu)
{
    struct allow_uid *allow = container_of(rcu, struct allow_uid, rcu);
    kvfree(allow);
}

struct su_profile profile_su_allow_uid(uid_t uid)
{
    rcu_read_lock();
    struct allow_uid *pos;
    struct su_profile profile = { 0 };
    list_for_each_entry_rcu(pos, &allow_uid_list, list)
    {
        if (pos->uid == uid) {
            memcpy(&profile, &pos->profile, sizeof(struct su_profile));
            rcu_read_unlock();
            return profile;
        }
    }
    rcu_read_unlock();
    return profile;
}
KP_EXPORT_SYMBOL(profile_su_allow_uid);

int is_su_allow_uid(uid_t uid)
{
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry_rcu(pos, &allow_uid_list, list)
    {
        if (pos->uid == uid) {
            rcu_read_unlock();
            return 1;
        }
    }
    rcu_read_unlock();
    return 0;
}
KP_EXPORT_SYMBOL(is_su_allow_uid);

int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext, int async)
{
    rcu_read_lock();
    struct allow_uid *pos, *old = 0;
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        if (pos->uid == uid) {
            old = pos;
            break;
        }
    }
    // todo: vmalloc -> kmalloc, gfp
    struct allow_uid *new = (struct allow_uid *)vmalloc(sizeof(struct allow_uid));
    new->uid = uid;
    new->profile.uid = uid;
    new->profile.to_uid = to_uid;
    strncpy(new->profile.scontext, scontext, sizeof(new->profile.scontext));
    new->profile.scontext[sizeof(new->profile.scontext) - 1] = '\0';

    spin_lock(&list_lock);
    if (old) { // update
        list_replace_rcu(&old->list, &new->list);
        logkfi("update uid: %d, to_uid: %d, sctx: %s\n", uid, new->profile.to_uid, new->profile.scontext);
    } else { // add new one
        list_add_rcu(&new->list, &allow_uid_list);
        logkfi("new uid: %d, to_uid: %d, sctx: %s\n", uid, new->profile.to_uid, new->profile.scontext);
    }
    spin_unlock(&list_lock);

    rcu_read_unlock();
    if (old) {
        if (async) {
            call_rcu(&old->rcu, allow_reclaim_callback);
        } else {
            synchronize_rcu();
            kvfree(old);
        }
    }
    return 0;
}
KP_EXPORT_SYMBOL(su_add_allow_uid);

int su_remove_allow_uid(uid_t uid, int async)
{
    struct allow_uid *pos;
    spin_lock(&list_lock);
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        if (pos->uid == uid) {
            list_del_rcu(&pos->list);
            spin_unlock(&list_lock);
            logkfi("uid: %d, to_uid: %d, sctx: %s\n", pos->uid, pos->profile.to_uid, pos->profile.scontext);
            if (async) {
                call_rcu(&pos->rcu, allow_reclaim_callback);
            } else {
                synchronize_rcu();
                kvfree(pos);
            }
            return 0;
        }
    }
    spin_unlock(&list_lock);
    return 0;
}
KP_EXPORT_SYMBOL(su_remove_allow_uid);

int su_allow_uid_nums()
{
    int num = 0;
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        num++;
    }
    rcu_read_unlock();
    logkfd("%d\n", num);
    return num;
}
KP_EXPORT_SYMBOL(su_allow_uid_nums);

int su_allow_uids(int is_user, uid_t *out_uids, int out_num)
{
    int rc = 0;
    int num = 0;
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        if (num >= out_num) goto out;

        uid_t uid = pos->profile.uid;
        if (is_user) {
            int cplen = compat_copy_to_user(out_uids + num, &uid, sizeof(uid));
            logkfd("uid: %d\n", uid);
            if (cplen <= 0) {
                logkfd("compat_copy_to_user error: %d", cplen);
                rc = cplen;
                goto out;
            }
        } else {
            out_uids[num] = uid;
        }

        num++;
    }
    rc = num;
out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(su_allow_uids);

int su_allow_uid_profile(int is_user, uid_t uid, struct su_profile *profile)
{
    int rc = -ENOENT;
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        if (pos->profile.uid != uid) continue;
        if (is_user) {
            int cplen = compat_copy_to_user(profile, &pos->profile, sizeof(struct su_profile));
            logkfd("profile: %d %d %s\n", uid, pos->profile.to_uid, pos->profile.scontext);
            if (cplen <= 0) {
                logkfd("compat_copy_to_user error: %d", cplen);
                rc = cplen;
                goto out;
            }
        } else {
            memcpy(profile, &pos->profile, sizeof(struct su_profile));
        }
        rc = 0;
        goto out;
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

// #define TRY_DIRECT_MODIFY_USER

#define INLINE_HOOK_SYSCALL

static void handle_before_execve(hook_local_t *hook_local, char **__user u_filename_p, char **__user uargv, void *udata)
{
#ifdef TRY_DIRECT_MODIFY_USER
    // copy to user len
    hook_local->data0 = 0;
#endif

    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        uid_t uid = current_uid();
        if (!is_su_allow_uid(uid)) return;
        struct su_profile profile = profile_su_allow_uid(uid);

        uid_t to_uid = profile.to_uid;
        const char *sctx = profile.scontext;
        commit_su(to_uid, sctx);

        struct file *filp = filp_open(apd_path, O_RDONLY, 0);
        if (!filp || IS_ERR(filp)) {
            int cplen = 0;
#ifdef TRY_DIRECT_MODIFY_USER
            cplen = compat_copy_to_user(*u_filename_p, sh_path, sizeof(sh_path));
            if (cplen > 0) {
                hook_local->data0 = cplen;
                hook_local->data1 = (uint64_t)u_filename_p;
                logkfi("call su uid: %d, to_uid: %d, sctx: %s, cplen: %d\n", uid, to_uid, sctx, cplen);
            }
#endif
            if (cplen <= 0) {
                void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
                if (uptr && !IS_ERR(uptr)) {
                    *u_filename_p = (char *__user)uptr;
                }
                logkfi("call su uid: %d, to_uid: %d, sctx: %s, uptr: %llx\n", uid, to_uid, sctx, uptr);
            }
        } else {
            filp_close(filp, 0);

            // command
            int cplen = 0;
#ifdef TRY_DIRECT_MODIFY_USER
            cplen = compat_copy_to_user(*u_filename_p, apd_path, sizeof(apd_path));
            if (cplen > 0) {
                hook_local->data0 = cplen;
                hook_local->data1 = (uint64_t)u_filename_p;
            }
#endif
            uint64_t sp = 0;
            if (cplen <= 0) {
                sp = current_user_stack_pointer();
                sp -= sizeof(apd_path);
                sp &= 0xFFFFFFFFFFFFFFF8;
                cplen = compat_copy_to_user((void *)sp, apd_path, sizeof(apd_path));
                if (cplen > 0) {
                    *u_filename_p = (char *)sp;
                }
            }

#ifdef ANDROID
            // argv
            int argv_cplen = 0;
            if (strcmp(legacy_su_path, filename)) {
#ifdef TRY_DIRECT_MODIFY_USER
                const char __user *p1 = get_user_arg_ptr(0, *uargv, 0);
                argv_cplen = compat_copy_to_user((void *__user)p1, legacy_su_path, sizeof(legacy_su_path));
#endif
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
#endif
        }

    } else if (!strcmp(SUPERCMD, filename)) {
        handle_supercmd(u_filename_p, uargv);
        return;
    }
}

#ifdef TRY_DIRECT_MODIFY_USER
static void handle_after_execve(hook_local_t *hook_local)
{
    int cplen = hook_local->data0;
    char **__user u_filename_p = (char **__user)hook_local->data1;
    if (cplen > 0) {
        compat_copy_to_user((void *)*u_filename_p, current_su_path, cplen);
    }
}
#endif

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
    handle_before_execve(&args->local, (char **)arg0p, (char **)arg1p, udata);
}

#ifdef TRY_DIRECT_MODIFY_USER
static void after_execve(hook_fargs3_t *args, void *udata)
{
    handle_after_execve(&args->local);
}
#else
#define after_execve 0
#endif

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2114
// COMPAT_SYSCALL_DEFINE5(execveat, int, fd,
// 		       const char __user *, filename,
// 		       const compat_uptr_t __user *, argv,
// 		       const compat_uptr_t __user *, envp,
// 		       int,  flags)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2095
// SYSCALL_DEFINE5(execveat, int, fd, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp, int, flags)
static void before_execveat(hook_fargs5_t *args, void *udata)
{
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    handle_before_execve(&args->local, (char **)arg1p, (char **)arg2p, udata);
}

#ifdef TRY_DIRECT_MODIFY_USER
static void after_execveat(hook_fargs5_t *args, void *udata)
{
    handle_after_execve(&args->local);
}
#else
#define after_execveat 0
#endif

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
    // copy to user len
    args->local.data0 = 0;

    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) return;

    char __user **u_filename_p = (char __user **)syscall_argn_p(args, 1);

    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, *u_filename_p, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        int cplen = 0;
#ifdef TRY_DIRECT_MODIFY_USER
        cplen = compat_copy_to_user(*u_filename_p, sh_path, sizeof(sh_path));
#endif
        if (cplen > 0) {
            args->local.data0 = cplen;
            args->local.data1 = (uint64_t)*u_filename_p;
            logkfi("su uid: %d, cp: %d\n", uid, cplen);
        } else {
            void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
            if (uptr && !IS_ERR(uptr)) {
                *u_filename_p = uptr;
            } else {
                logkfi("su uid: %d, cp stack error: %d\n", uid, uptr);
            }
        }
    }
}

#ifdef TRY_DIRECT_MODIFY_USER
static void su_handler_arg1_ufilename_after(hook_fargs6_t *args, void *udata)
{
    int cplen = args->local.data0;
    if (cplen > 0) {
        compat_copy_to_user((void *)args->local.data1, current_su_path, cplen);
    }
}
#else
#define su_handler_arg1_ufilename_after 0
#endif

int su_compat_init()
{
    current_su_path = default_su_path;

    INIT_LIST_HEAD(&allow_uid_list);
    spin_lock_init(&list_lock);

    // default shell
    su_add_allow_uid(2000, 0, ALL_ALLOW_SCONTEXT, 1);

    hook_err_t rc = HOOK_NO_ERR;

    rc = hook_syscalln(__NR_execve, 3, before_execve, after_execve, (void *)0);
    log_boot("hook __NR_execve rc: %d\n", rc);

    rc = hook_syscalln(__NR_execveat, 5, before_execveat, after_execveat, (void *)0);
    log_boot("hook __NR_execveat rc: %d\n", rc);

    rc = hook_syscalln(__NR3264_fstatat, 4, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after,
                       (void *)0);
    log_boot("hook __NR3264_fstatat rc: %d\n", rc);

    rc = hook_syscalln(__NR_statx, 5, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook __NR_statx rc: %d\n", rc);

    rc = hook_syscalln(__NR_faccessat, 3, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook __NR_faccessat rc: %d\n", rc);

    rc =
        hook_syscalln(__NR_faccessat2, 4, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook __NR_faccessat2 rc: %d\n", rc);

    // #include <asm/unistd32.h>

    // __NR_execve 11
    rc = hook_compat_syscalln(11, 3, before_execve, after_execve, (void *)1);
    log_boot("hook 32 __NR_execve rc: %d\n", rc);

    //  __NR_execveat 387
    rc = hook_compat_syscalln(387, 5, before_execveat, after_execveat, (void *)1);
    log_boot("hook 32 __NR_execveat rc: %d\n", rc);

    // __NR_statx 397
    rc = hook_compat_syscalln(397, 5, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook 32 __NR_statx rc: %d\n", rc);

    // #define __NR_stat 106
    // #define __NR_lstat 107
    // #define __NR_stat64 195
    // #define __NR_lstat64 196

    // __NR_fstatat64 327
    rc = hook_compat_syscalln(327, 4, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook 32 __NR_fstatat64 rc: %d\n", rc);

    //  __NR_faccessat 334
    rc = hook_compat_syscalln(334, 3, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook 32 __NR_faccessat rc: %d\n", rc);

    // __NR_faccessat2 439
    rc = hook_compat_syscalln(439, 4, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook 32 __NR_faccessat2 rc: %d\n", rc);

    return rc;
}