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
#include <uapi/linux/limits.h>

static const char sh_path[] = ANDROID_SH_PATH;
static const char default_su_path[] = ANDROID_SU_PATH;
static const char *current_su_path = 0;
static const char apd_path[] = APD_PATH;

struct allow_uid
{
    uid_t uid;
    struct su_profile profile;
    struct list_head list;
    struct rcu_head rcu;
};

static struct list_head allow_uid_list;
static spinlock_t list_lock;

static void allow_reclaim_callback(struct rcu_head *rcu)
{
    struct allow_uid *allow = container_of(rcu, struct allow_uid, rcu);
    kvfree(allow);
}

static struct su_profile *search_allow_uid(uid_t uid)
{
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry_rcu(pos, &allow_uid_list, list)
    {
        if (pos->uid == uid) {
            // make a deep copy
            // todo: use stack
            struct su_profile *profile = (struct su_profile *)vmalloc(sizeof(struct su_profile));
            memcpy(profile, &pos->profile, sizeof(struct su_profile));
            rcu_read_unlock();
            return profile;
        }
    }
    rcu_read_unlock();
    return 0;
}

static int is_allow_uid(uid_t uid)
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

#define TRY_DIRECT_MODIFY_USER

static void handle_before_execve(hook_local_t *hook_local, char **__user u_filename_p, char **__user uargv, void *udata)
{
    // copy to user len
    hook_local->data0 = 0;

    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compact_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        uid_t uid = current_uid();
        struct su_profile *profile = search_allow_uid(uid);
        if (!profile) return;

        uid_t to_uid = profile->to_uid;
        const char *sctx = profile->scontext;
        commit_su(to_uid, sctx);

        struct file *filp = filp_open(apd_path, O_RDONLY, 0);
        if (!filp || IS_ERR(filp)) {
            int cplen = 0;
#ifdef TRY_DIRECT_MODIFY_USER
            cplen = compat_copy_to_user(*u_filename_p, sh_path, sizeof(sh_path));
#endif
            if (cplen > 0) {
                hook_local->data0 = cplen;
                hook_local->data1 = (uint64_t)u_filename_p;
            } else {
                void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
                if (uptr && !IS_ERR(uptr)) {
                    *u_filename_p = (char *__user)uptr;
                }
            }
            logkfi("call su uid: %d, to_uid: %d, sctx: %s, cplen: %d\n", uid, to_uid, sctx, cplen);
        } else {
            filp_close(filp, 0);
            // command
            int cplen = 0;
#ifdef TRY_DIRECT_MODIFY_USER
            cplen = compat_copy_to_user(*u_filename_p, apd_path, sizeof(apd_path));
#endif
            uint64_t sp = 0;
            if (cplen > 0) {
                hook_local->data0 = cplen;
                hook_local->data1 = (uint64_t)u_filename_p;
            } else {
                sp = current_user_stack_pointer();
                sp -= sizeof(apd_path);
                sp &= 0xFFFFFFFFFFFFFFF8;
                cplen = compat_copy_to_user((void *)sp, apd_path, sizeof(apd_path));
                if (cplen > 0) {
                    *u_filename_p = (char *)sp;
                }
            }

            // args0
            int argv_cplen = 0;
#ifdef TRY_DIRECT_MODIFY_USER
            const char __user *p1 = get_user_arg_ptr(0, *uargv, 0);
            argv_cplen = compat_copy_to_user((void *__user)p1, default_su_path, sizeof(default_su_path));
#endif
            if (argv_cplen <= 0) {
                sp = sp ?: current_user_stack_pointer();
                sp -= sizeof(default_su_path);
                sp &= 0xFFFFFFFFFFFFFFF8;
                argv_cplen = compat_copy_to_user((void *)sp, default_su_path, sizeof(default_su_path));
                if (argv_cplen > 0) {
                    int rc = set_user_arg_ptr(0, *uargv, 0, sp);
                    if (rc < 0) { // todo: modify entire argv
                    }
                }
            }
            logkfi("call apd uid: %d, to_uid: %d, sctx: %s, cplen: %d, %d\n", uid, to_uid, sctx, cplen, argv_cplen);
        }
        kvfree(profile);
    } else if (!strcmp(SUPERCMD, filename)) {
        // key
        const char __user *p1 = get_user_arg_ptr(0, *uargv, 1);
        if (!p1 || IS_ERR(p1)) return;

        // auth key
        char arg1[SUPER_KEY_LEN];
        if (compact_strncpy_from_user(arg1, p1, sizeof(arg1)) <= 0) return;
        if (superkey_auth(arg1)) return;

        commit_su(0, 0);

        // real command
#define EMBEDDED_NAME_MAX (PATH_MAX - sizeof(*filename) - 128) // enough

        const char *exec = sh_path;
        int exec_len = sizeof(sh_path);
        const char __user *p2 = get_user_arg_ptr(0, *uargv, 2);

        if (p1 && !IS_ERR(p2)) {
            char buffer[EMBEDDED_NAME_MAX];
            int len = compact_strncpy_from_user(buffer, p2, EMBEDDED_NAME_MAX);
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
        *uargv += 2 * 8;
    }
}

static void handle_after_execve(hook_local_t *hook_local)
{
    int cplen = hook_local->data0;
    char **__user u_filename_p = (char **__user)hook_local->data1;
    if (cplen > 0) {
        compat_copy_to_user((void *)*u_filename_p, current_su_path, cplen);
    }
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2087
// SYSCALL_DEFINE3(execve, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp)
static void before_execve(hook_fargs3_t *args, void *udata)
{
    void *arg0p = syscall_argn_p(args, 0);
    void *arg1p = syscall_argn_p(args, 1);
    handle_before_execve(&args->local, (char **)arg0p, (char **)arg1p, udata);
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
    handle_before_execve(&args->local, (char **)arg1p, (char **)arg2p, udata);
}

static void after_execveat(hook_fargs5_t *args, void *udata)
{
    handle_after_execve(&args->local);
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
    // copy to user len
    args->local.data0 = 0;

    uid_t uid = current_uid();
    if (!is_allow_uid(uid)) return;

    char __user *ufilename = (char __user *)syscall_argn(args, 1);
    char filename[SU_PATH_MAX_LEN];
    int flen = compact_strncpy_from_user(filename, ufilename, sizeof(filename));
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

static void su_handler_arg1_ufilename_after(hook_fargs6_t *args, void *udata)
{
    int cplen = args->local.data0;
    if (cplen > 0) {
        compat_copy_to_user((void *)args->local.data1, current_su_path, cplen);
    }
}

int su_compat_init()
{
    current_su_path = default_su_path;

    INIT_LIST_HEAD(&allow_uid_list);
    spin_lock_init(&list_lock);

    // default shell
    struct su_profile default_shell_profile = {
        .uid = 2000,
        .to_uid = 0,
    };
    su_add_allow_uid(default_shell_profile.uid, &default_shell_profile, 1);

    hook_err_t rc = HOOK_NO_ERR;

    rc = inline_hook_syscalln(__NR_execve, 3, before_execve, after_execve, (void *)__NR_execve);
    log_boot("hook rc: %d\n", rc);

    rc = inline_hook_syscalln(__NR_execveat, 5, before_execveat, after_execveat, (void *)__NR_execveat);
    log_boot("hook rc: %d\n", rc);

    rc = inline_hook_syscalln(__NR3264_fstatat, 4, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after,
                              (void *)__NR3264_fstatat);
    log_boot("hook rc: %d\n", rc);

    rc = inline_hook_syscalln(__NR_faccessat, 3, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after,
                              (void *)__NR_faccessat);
    log_boot("hook rc: %d\n", rc);

    rc = inline_hook_syscalln(__NR_faccessat2, 4, su_handler_arg1_ufilename_before, su_handler_arg1_ufilename_after,
                              (void *)__NR_faccessat2);
    log_boot("hook rc: %d\n", rc);

    return rc;
}