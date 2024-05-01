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

static const char sh_path[] = ANDROID_SH_PATH;
static const char default_su_path[] = ANDROID_SU_PATH;
static const char legacy_su_path[] = ANDROID_LEGACY_SU_PATH;
static const char *current_su_path = 0;
static const char apd_path[] = APD_PATH;

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

int su_add_allow_uid(uid_t uid, struct su_profile *profile, int async)
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
    struct allow_uid *new = (struct allow_uid *)vmalloc(sizeof(struct allow_uid));
    new->uid = profile->uid;
    memcpy(&new->profile, profile, sizeof(struct su_profile));
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

int su_allow_uids(uid_t *__user uuids, int unum)
{
    int rc = 0;
    int num = 0;
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        if (num >= unum) {
            goto out;
        }
        uid_t uid = pos->profile.uid;
        int cplen = compat_copy_to_user(uuids + num, &uid, sizeof(uid));
        logkfd("uid: %d\n", uid);
        if (cplen <= 0) {
            logkfd("compat_copy_to_user error: %d", cplen);
            rc = cplen;
            goto out;
        }
        num++;
    }
    rc = num;
out:
    rcu_read_unlock();
    return rc;
}

int su_allow_uid_profile(uid_t uid, struct su_profile *__user uprofile)
{
    int rc = -ENOENT;
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        if (pos->profile.uid != uid) continue;
        int cplen = compat_copy_to_user(uprofile, &pos->profile, sizeof(struct su_profile));
        logkfd("profile: %d %d %s\n", uid, pos->profile.to_uid, pos->profile.scontext);
        if (cplen <= 0) {
            logkfd("compat_copy_to_user error: %d", cplen);
            rc = cplen;
            goto out;
        }
        rc = 0;
        goto out;
    }
out:
    rcu_read_unlock();
    return rc;
}

// no free, no lock
int su_reset_path(const char *path)
{
    if (!path) return -EINVAL;
    int len = strlen(path);
    if (len <= 0) return -EINVAL;
    char *new_su_path = vmalloc(len + 1);
    if (!new_su_path) return -ENOMEM;
    strcpy(new_su_path, path);
    new_su_path[len] = '\0';
    current_su_path = new_su_path;
    dsb(ishst);
    logkfi("%s\n", current_su_path);
    return 0;
}

int su_get_path(char *__user ubuf, int buf_len)
{
    if (!current_su_path) {
        logkfi("null su path\n");
        current_su_path = default_su_path;
    }
    int len = strnlen(current_su_path, SU_PATH_MAX_LEN);
    if (len <= 0) return -EINVAL;
    if (buf_len < len) return -ENOBUFS;
    logkfi("%s\n", current_su_path);
    return compat_copy_to_user(ubuf, current_su_path, len + 1);
}

// todo: rcu_dereference_protected
static uid_t current_uid()
{
    struct cred *cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
    return uid;
}

// #define SU_COMPAT_INLINE_HOOK

#ifdef SU_COMPAT_INLINE_HOOK

// int do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
// int __do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags,
//                      struct file *file);
// static int do_execve_common(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp)
static void before_do_execve(hook_fargs8_t *args, void *udata)
{
    struct filename *filename;
    int filename_index = 1;

    if (udata && (((uintptr_t)args->arg0) & 0xF000000000000000) == 0xF000000000000000) {
        // int, AT_FDCWD(ffffff9c) or fd
        filename_index = 0;
    }

    filename = (struct filename *)args->args[filename_index];
    if (!filename || IS_ERR(filename)) return;

    if (!strcmp(current_su_path, filename->name)) {
        uid_t uid = current_uid();
        if (!is_su_allow_uid(uid)) return;
        struct su_profile profile = profile_su_allow_uid(uid);

        uid_t to_uid = profile.to_uid;
        const char *sctx = profile.scontext;
        commit_su(to_uid, sctx);

        struct file *filp = filp_open(apd_path, O_RDONLY, 0);
        if (!filp || IS_ERR(filp)) {
            logkfi("call su uid: %d, to_uid: %d, sctx: %s\n", uid, to_uid, sctx);
            strcpy((char *)filename->name, sh_path);
        } else {
            filp_close(filp, 0);
            strcpy((char *)filename->name, apd_path);
            int cplen = 0;
            if (strcmp(legacy_su_path, filename->name)) {
                const char *__user p0 =
                    get_user_arg_ptr((void *)args->args[filename_index + 1], (void *)args->args[filename_index + 2], 0);
                cplen = compat_copy_to_user((char *__user)p0, legacy_su_path, sizeof(legacy_su_path));
            }
            logkfi("call apd uid: %d, to_uid: %d, sctx: %s, cplen: %d\n", uid, to_uid, sctx, cplen);
        }
    } else if (!strcmp(SUPERCMD, filename->name)) {
        void *ua0 = (void *)args->args[filename_index + 1];
        void *ua1 = (void *)args->args[filename_index + 2];

        // key
        const char __user *p1 = get_user_arg_ptr(ua0, ua1, 1);
        if (IS_ERR(p1)) return;

        // auth skey
        char arg1[SUPER_KEY_LEN];
        if (compat_strncpy_from_user(arg1, p1, sizeof(arg1)) <= 0) return;
        if (auth_superkey(arg1)) return;

        commit_su(0, 0);

        // real command
#define EMBEDDED_NAME_MAX (PATH_MAX - sizeof(*filename) - 128) // enough

        const char __user *p2 = get_user_arg_ptr(ua0, ua1, 2);
        if (!p2 || IS_ERR(p2)) {
            strcpy((char *)filename->name, sh_path);
        } else {
            compat_strncpy_from_user((char *)filename->name, p2, EMBEDDED_NAME_MAX);
        }
        logkfi("supercmd %s\n", filename->name);

        // shift args
        args->args[filename_index + (has_config_compat ? 2 : 1)] += 2 * ((has_config_compat && ua0) ? 4 : 8);
    }
    return;
}

// SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
// SYSCALL_DEFINE4(faccessat2, int, dfd, const char __user *, filename, int, mode, int, flags)
static void before_faccessat(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) return;

    char __user *filename = (char __user *)syscall_argn(args, 1);

    char buf[SU_PATH_MAX_LEN];
    compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (strcmp(current_su_path, buf)) return;

    logkfd("uid: %d\n", uid);
    args->ret = 0;
    args->skip_origin = 1;
}

// SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename, struct stat __user *, statbuf, int, flag)
static void before_sysfstatat(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) return;

    char *__user filename = (char *__user)syscall_argn(args, 1);

    char buf[SU_PATH_MAX_LEN];
    compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (!strcmp(current_su_path, buf)) {
        void *__user uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
        if (uptr && !IS_ERR(uptr)) set_syscall_argn(args, 1, (uint64_t)uptr);
        logkfd("uid: %d, %llx\n", uid, uptr);
    }
    return;
}

// int vfs_statx(int dfd, struct filename *filename, int flags, struct kstat *stat, u32 request_mask)
// int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
// int vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
// static void before_stat(hook_fargs8_t *args, void *udata)
// {
//     uid_t uid = current_uid();
//     if (!is_su_allow_uid(uid)) return;

//     if ((args->arg1 & 0xF000000000000000) == 0xF000000000000000) {
//         struct filename *filename = (struct filename *)args->arg1;
//         if (IS_ERR(filename)) return;
//         if (!strcmp(current_su_path, filename->name)) {
//             logkfd("0 uid: %d\n", uid);
//             strcpy((char *)filename->name, sh_path);
//             return;
//         }
//     } else {
//         char __user *filename = (char __user *)args->arg1;
//         char buf[SU_PATH_MAX_LEN];
//         compat_strncpy_from_user(buf, filename, sizeof(buf));
//         if (!strcmp(current_su_path, buf)) {
//             void *__user uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
//             args->arg1 = (uint64_t)uptr;
//             logkfd("1 uid: %d, %llx\n", uid, uptr);
//         }
//         return;
//     }
// }

#else // SU_COMPAT_INLINE_HOOK

// #define TRY_DIRECT_MODIFY_USER

static void handle_before_execve(hook_local_t *hook_local, char **__user u_filename_p, char **__user uargv, void *udata)
{
#ifdef TRY_DIRECT_MODIFY_USER
    // copy to user len
    hook_local->data0 = 0;
#endif

    void *is_compact = udata;

    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (unlikely(flen <= 0)) return;

    if (unlikely(!strcmp(current_su_path, filename))) {
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

            // argv
            int argv_cplen = 0;
            if (strcmp(legacy_su_path, filename)) {
#ifdef TRY_DIRECT_MODIFY_USER
                const char __user *p1 = get_user_arg_ptr(is_compact, *uargv, 0);
                argv_cplen = compat_copy_to_user((void *__user)p1, legacy_su_path, sizeof(legacy_su_path));
#endif
                if (argv_cplen <= 0) {
                    sp = sp ?: current_user_stack_pointer();
                    sp -= sizeof(legacy_su_path);
                    sp &= 0xFFFFFFFFFFFFFFF8;
                    argv_cplen = compat_copy_to_user((void *)sp, legacy_su_path, sizeof(legacy_su_path));
                    if (argv_cplen > 0) {
                        int rc = set_user_arg_ptr(is_compact, *uargv, 0, sp);
                        if (rc < 0) { // todo: modify entire argv
                            logkfi("call apd argv error, uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, sctx,
                                   rc);
                        }
                    }
                }
            }
            logkfi("call apd uid: %d, to_uid: %d, sctx: %s, cplen: %d, %d\n", uid, to_uid, sctx, cplen, argv_cplen);
        }

    } else if (unlikely(!strcmp(SUPERCMD, filename))) {
        // key
        const char __user *p1 = get_user_arg_ptr(is_compact, *uargv, 1);
        if (!p1 || IS_ERR(p1)) return;

        // auth key
        char arg1[SUPER_KEY_LEN];
        if (compat_strncpy_from_user(arg1, p1, sizeof(arg1)) <= 0) return;
        if (auth_superkey(arg1)) return;

        commit_su(0, 0);

        // real command
#define EMBEDDED_NAME_MAX (PATH_MAX - sizeof(*filename) - 128) // enough

        const char *exec = sh_path;
        int exec_len = sizeof(sh_path);
        const char __user *p2 = get_user_arg_ptr(is_compact, *uargv, 2);

        if (p1 && !IS_ERR(p2)) {
            char buffer[EMBEDDED_NAME_MAX];
            int len = compat_strncpy_from_user(buffer, p2, EMBEDDED_NAME_MAX);
            if (len >= 0) {
                exec = buffer;
                exec_len = len;
            }
        }

        int cplen = 0;
#ifdef TRY_DIRECT_MODIFY_USER
        cplen = compat_copy_to_user(*u_filename_p, exec, exec_len);
#endif
        if (cplen <= 0) *u_filename_p = copy_to_user_stack(exec, exec_len);

        // shift args
        *uargv += 2 * (is_compact ? 4 : 8);
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

    char __user *ufilename = (char __user *)syscall_argn(args, 1);
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        int cplen = 0;
#ifdef TRY_DIRECT_MODIFY_USER
        cplen = compat_copy_to_user(ufilename, sh_path, sizeof(sh_path));
#endif
        if (cplen > 0) {
            args->local.data0 = cplen;
            args->local.data1 = (uint64_t)ufilename;
            // logkfi("su uid: %d, cp: %d\n", uid, cplen);
        } else {
            void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
            if (uptr && !IS_ERR(uptr)) {
                set_syscall_argn(args, 1, (uint64_t)uptr);
            }
            // logkfi("su uid: %d, cp stack: %llx\n", uid, uptr);
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

#endif // SU_COMPAT_INLINE_HOOK

int su_compat_init()
{
    current_su_path = default_su_path;

    INIT_LIST_HEAD(&allow_uid_list);
    spin_lock_init(&list_lock);

    // default shell
    struct su_profile default_allow_profile = {
        .uid = 2000,
        .to_uid = 0,
        .scontext = ALL_ALLOW_SCONTEXT,
    };
    su_add_allow_uid(default_allow_profile.uid, &default_allow_profile, 1);

    // default root
    default_allow_profile.uid = 0;
    su_add_allow_uid(default_allow_profile.uid, &default_allow_profile, 1);

    hook_err_t rc = HOOK_NO_ERR;

#ifdef SU_COMPAT_INLINE_HOOK

    struct patch_symbol *symbol = get_preset_patch_sym();

    if (symbol->do_execveat_common) { // [5.9.0, ) or [3.19, 4.19]
        rc = hook_wrap8((void *)symbol->do_execveat_common, (void *)before_do_execve, 0, 0);
        log_boot("hook do_execveat_common rc: %d\n", rc);
    } else if (symbol->__do_execve_file) { // [4.19, 5.9)
        rc = hook_wrap8((void *)symbol->__do_execve_file, (void *)before_do_execve, 0, 0);
        log_boot("hook __do_execve_file rc: %d\n", rc);
    } else if (symbol->do_execve_common) { // (, 3.19)
        rc = hook_wrap8((void *)symbol->do_execve_common, (void *)before_do_execve, 0, (void *)1);
        log_boot("hook do_execve_common rc: %d\n", rc);
    }

    if (symbol->sys_faccessat) {
        rc = hook_wrap4((void *)symbol->sys_faccessat, (void *)before_faccessat, 0, (void *)1);
        log_boot("hook sys_faccessat rc: %d\n", rc);
    }
    if (symbol->sys_faccessat2) {
        rc = hook_wrap4((void *)symbol->sys_faccessat2, (void *)before_faccessat, 0, (void *)1);
        log_boot("hook sys_faccessat2 rc: %d\n", rc);
    }

    if (symbol->sys_newfstatat) {
        rc = hook_wrap4((void *)symbol->sys_newfstatat, (void *)before_sysfstatat, 0, (void *)1);
        log_boot("hook sys_newfstatat rc: %d\n", rc);
    }

#else

    rc = fp_hook_syscalln(__NR_execve, 3, before_execve, after_execve, (void *)0);
    log_boot("hook __NR_execve rc: %d\n", rc);

    rc = fp_hook_syscalln(__NR_execveat, 5, before_execveat, after_execveat, (void *)0);
    log_boot("hook __NR_execveat rc: %d\n", rc);

    rc = fp_hook_syscalln(__NR3264_fstatat, 4, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after,
                          (void *)0);
    log_boot("hook __NR3264_fstatat rc: %d\n", rc);

    rc = fp_hook_syscalln(__NR_statx, 5, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook __NR_statx rc: %d\n", rc);

    rc = fp_hook_syscalln(__NR_faccessat, 3, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after,
                          (void *)0);
    log_boot("hook __NR_faccessat rc: %d\n", rc);

    rc = fp_hook_syscalln(__NR_faccessat2, 4, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after,
                          (void *)0);
    log_boot("hook __NR_faccessat2 rc: %d\n", rc);

    // #include <asm/unistd32.h>

    // __NR_execve 11
    rc = fp_hook_compat_syscalln(11, 3, before_execve, after_execve, (void *)1);
    log_boot("hook 32 __NR_execve rc: %d\n", rc);

    //  __NR_execveat 387
    rc = fp_hook_compat_syscalln(387, 5, before_execveat, after_execveat, (void *)1);
    log_boot("hook 32 __NR_execveat rc: %d\n", rc);

    // __NR_statx 397
    rc = fp_hook_compat_syscalln(397, 5, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook 32 __NR_statx rc: %d\n", rc);

    // #define __NR_stat 106
    // #define __NR_lstat 107
    // #define __NR_stat64 195
    // #define __NR_lstat64 196

    // __NR_fstatat64 327
    rc = fp_hook_compat_syscalln(327, 4, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook 32 __NR_fstatat64 rc: %d\n", rc);

    //  __NR_faccessat 334
    rc = fp_hook_compat_syscalln(334, 3, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook 32 __NR_faccessat rc: %d\n", rc);

    // __NR_faccessat2 439
    rc = fp_hook_compat_syscalln(439, 4, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after, (void *)0);
    log_boot("hook 32 __NR_faccessat2 rc: %d\n", rc);

#endif

    return rc;
}