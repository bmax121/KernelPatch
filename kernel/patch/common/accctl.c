/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "accctl.h"

#include <pgtable.h>
#include <ksyms.h>
#include <taskext.h>
#include <linux/spinlock.h>
#include <linux/capability.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/seccomp.h>
#include <asm/thread_info.h>
#include <uapi/asm-generic/errno.h>

int set_priv_selinx_allow(struct task_struct *task, int val)
{
    struct task_ext *ext = get_task_ext(task);
    ext->priv_selinux_allow = val;
    dsb(ish);
    return 0;
}

static void su_cred(struct cred *cred, uid_t uid)
{
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_inheritable_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_permitted_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_effective_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_bset_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_ambient_offset) = full_cap;

    *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.euid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.fsuid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.suid_offset) = uid;

    *(uid_t *)((uintptr_t)cred + cred_offset.gid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.egid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.fsgid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.sgid_offset) = uid;
}

// int commit_kernel_cred()
// {
//     int rc = 0;
//     struct task_struct *task = current;
//     struct task_ext *ext = get_task_ext(task);
//     if (!task_ext_valid(ext)) goto out;

//     const struct cred *old = get_task_cred(task);
//     struct cred *new = prepare_kernel_cred(0);
//     u32 secid;
//     if (kfunc(security_cred_getsecid)) {
//         kfunc(security_cred_getsecid)(old, &secid);
//         set_security_override(new, secid);
//     }
//     commit_creds(new);
// out:
//     return rc;
// }

int commit_su(uid_t to_uid, const char *sctx)
{
    int rc = 0;
    struct task_struct *task = current;
    struct task_ext *ext = get_task_ext(task);
    if (unlikely(!task_ext_valid(ext))) {
        logkfe("dirty task_ext, pid(maybe dirty): %d\n", ext->pid);
        rc = -ENOMEM;
        goto out;
    }

    struct thread_info *thi = current_thread_info();
    thi->flags &= ~(_TIF_SECCOMP);

    if (likely(task_struct_offset.comm_offset > 0)) {
        struct seccomp *seccomp = (struct seccomp *)((uintptr_t)task + task_struct_offset.seccomp_offset);
        seccomp->mode = SECCOMP_MODE_DISABLED;
        // only be called when the task is exiting, so no barriers
        // todo: WARN_ON(tsk->sighand != NULL);
        // seccomp_filter_release(task);
    }

    ext->selinux_allow = 1;
    struct cred *new = prepare_creds();
    su_cred(new, to_uid);

    struct group_info *group_info = groups_alloc(0);
    set_groups(new, group_info);

    if (sctx && sctx[0]) ext->selinux_allow = !!set_security_override_from_ctx(new, sctx);
    commit_creds(new);

out:
    logkfi("pid: %d, tgid: %d, to_uid: %d, sctx: %s, via_hook: %d\n", ext->pid, ext->tgid, to_uid, sctx,
           ext->selinux_allow);
    return rc;
}

// todo: rcu
int task_su(pid_t pid, uid_t to_uid, const char *sctx)
{
    int rc = 0;
    int scontext_changed = 0;
    struct task_struct *task = find_get_task_by_vpid(pid);
    if (unlikely(!task)) {
        logkfe("no such pid: %d\n", pid);
        return -ESRCH;
    }
    struct task_ext *ext = get_task_ext(task);

    if (unlikely(!task_ext_valid(ext))) {
        logkfe("dirty task_ext, pid(maybe dirty): %d\n", ext->pid);
        rc = -ENOMEM;
        goto out;
    }

    struct thread_info *thi = get_task_thread_info(task);
    thi->flags &= ~(_TIF_SECCOMP);

    if (likely(task_struct_offset.comm_offset > 0)) {
        struct seccomp *seccomp = (struct seccomp *)((uintptr_t)task + task_struct_offset.seccomp_offset);
        seccomp->mode = SECCOMP_MODE_DISABLED;
        // only be called when the task is exiting, so no barriers
        // todo: WARN_ON(tsk->sighand != NULL);
        // seccomp_filter_release(task);
    }

    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    su_cred(cred, to_uid);
    if (sctx && sctx[0]) scontext_changed = !set_security_override_from_ctx(cred, sctx);

    struct cred *real_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset);
    if (cred != real_cred) {
        su_cred(real_cred, to_uid);
        if (sctx && sctx[0]) scontext_changed = scontext_changed && !set_security_override_from_ctx(real_cred, sctx);
    }
    ext->priv_selinux_allow = !scontext_changed;

    logkfi("pid: %d, tgid: %d, to_uid: %d, sctx: %s, via_hook: %d\n", ext->pid, ext->tgid, to_uid, sctx,
           ext->priv_selinux_allow);
out:
    return rc;
}
