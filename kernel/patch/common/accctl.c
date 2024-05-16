/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "accctl.h"

#include <pgtable.h>
#include <ksyms.h>
#include <taskext.h>
#include <uapi/scdefs.h>
#include <linux/spinlock.h>
#include <linux/capability.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <asm/thread_info.h>
#include <uapi/asm-generic/errno.h>
#include <hook.h>
#include <linux/string.h>
#include <security/selinux/include/avc.h>
#include <security/selinux/include/security.h>
#include <predata.h>
#include <linux/slab.h>

char all_allow_sctx[SUPERCALL_SCONTEXT_LEN] = { '\0' };
int allow_sid_enable = 0;
uint32_t all_allow_sid = 0;

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

int set_all_allow_sctx(const char *sctx)
{
    if (!sctx || !sctx[0]) {
        all_allow_sctx[0] = 0;
        all_allow_sid = 0;
        dsb(ish);
        allow_sid_enable = 0;
        dsb(ish);
        logkfd("clear all allow sconetxt\n");
        return 0;
    }

    int rc = security_secctx_to_secid(sctx, strlen(sctx), &all_allow_sid);
    if (!rc) {
        strncpy(all_allow_sctx, sctx, sizeof(all_allow_sctx) - 1);
        all_allow_sctx[sizeof(all_allow_sctx) - 1] = '\0';
        dsb(ish);
        allow_sid_enable = 1;
        dsb(ish);
        logkfd("set all allow sconetxt: %s, sid: %d\n", all_allow_sctx, all_allow_sid);
    }
    return rc;
}

int commit_kernel_su()
{
    struct cred *new = prepare_kernel_cred(0);
    set_security_override(new, all_allow_sid);
    return commit_creds(new);
}

int commit_common_su(uid_t to_uid, const char *sctx)
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

    if (task_struct_offset.comm_offset > 0) {
        struct seccomp *seccomp = (struct seccomp *)((uintptr_t)task + task_struct_offset.seccomp_offset);
        seccomp->mode = SECCOMP_MODE_DISABLED;
        // only be called when the task is exiting, so no barriers
        // todo: WARN_ON(tsk->sighand != NULL);
        // seccomp_filter_release(task);
    }

    ext->sel_allow = 1;
    struct cred *new = prepare_creds();
    su_cred(new, to_uid);

    struct group_info *group_info = groups_alloc(0);
    set_groups(new, group_info);

    if (sctx && sctx[0]) {
        ext->sel_allow = !!set_security_override_from_ctx(new, sctx);
    }
    commit_creds(new);

out:
    logkfi("pid: %d, tgid: %d, to_uid: %d, sctx: %s, via_hook: %d\n", ext->pid, ext->tgid, to_uid, sctx,
           ext->sel_allow);
    return rc;
}

int commit_su(uid_t to_uid, const char *sctx)
{
    if (unlikely(allow_sid_enable) && !to_uid) {
        return commit_kernel_su();
    } else {
        return commit_common_su(to_uid, sctx);
    }
}

// todo: rcu
int task_su(pid_t pid, uid_t to_uid, const char *sctx)
{
    int rc = 0;
    int scontext_changed = 0;
    struct task_struct *task = find_get_task_by_vpid(pid);
    if (!task) {
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

    if (task_struct_offset.comm_offset > 0) {
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
    ext->priv_sel_allow = !scontext_changed;

    logkfi("pid: %d, tgid: %d, to_uid: %d, sctx: %s, via_hook: %d\n", ext->pid, ext->tgid, to_uid, sctx,
           ext->priv_sel_allow);
out:
    return rc;
}

static int (*avc_denied_backup)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
                                void *driver, void *xperm, void *flags, struct av_decision *avd) = 0;

static int avc_denied_replace(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass, void *_requested,
                              void *_driver, void *_xperm, void *_flags, struct av_decision *_avd)
{
    if (unlikely(allow_sid_enable)) {
        u32 ssid = (u32)(u64)_ssid;
        if ((uint64_t)_state <= 0xffffffffL) {
            ssid = (u32)(u64)_state;
        }
        if (ssid == all_allow_sid) {
            goto allow;
        }
    }

    struct task_ext *ext = get_current_task_ext();
    if (unlikely(task_ext_valid(ext) && (ext->sel_allow || ext->priv_sel_allow))) {
        goto allow;
    }

    int rc = avc_denied_backup(_state, _ssid, _tsid, _tclass, _requested, _driver, _xperm, _flags, _avd);
    return rc;

allow:
    struct av_decision *avd = (struct av_decision *)_avd;
    if ((uint64_t)_state <= 0xffffffffL) {
        avd = (struct av_decision *)_flags;
    }
    avd->allowed = 0xffffffff;
    avd->auditallow = 0;
    avd->auditdeny = 0;
    return 0;
}

static int (*slow_avc_audit_backup)(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass,
                                    void *_requested, void *_audited, void *_denied, void *_result,
                                    struct common_audit_data *_a) = 0;

static int slow_avc_audit_replace(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass,
                                  void *_requested, void *_audited, void *_denied, void *_result,
                                  struct common_audit_data *_a)
{
    if (allow_sid_enable) {
        u32 ssid = (u64)_ssid;
        if ((uint64_t)_state <= 0xffffffffL) {
            ssid = (u64)_state;
        }
        if (ssid == all_allow_sid) {
            return 0;
        }
    }

    struct task_ext *ext = get_current_task_ext();
    if (unlikely(task_ext_valid(ext) && (ext->sel_allow || ext->priv_sel_allow))) {
        return 0;
    }

    int rc = slow_avc_audit_backup(_state, _ssid, _tsid, _tclass, _requested, _audited, _denied, _result, _a);
    return rc;
}

int bypass_selinux()
{
    unsigned long avc_denied_addr = get_preset_patch_sym()->avc_denied;
    if (avc_denied_addr) {
        hook_err_t err = hook((void *)avc_denied_addr, (void *)avc_denied_replace, (void **)&avc_denied_backup);
        if (err != HOOK_NO_ERR) {
            log_boot("hook avc_denied_addr: %llx, error: %d\n", avc_denied_addr, err);
        }
    }

    unsigned long slow_avc_audit_addr = get_preset_patch_sym()->slow_avc_audit;
    if (slow_avc_audit_addr) {
        hook_err_t err =
            hook((void *)slow_avc_audit_addr, (void *)slow_avc_audit_replace, (void **)&slow_avc_audit_backup);
        if (err != HOOK_NO_ERR) {
            log_boot("hook slow_avc_audit: %llx, error: %d\n", slow_avc_audit_addr, err);
        }
    }

    return 0;
}
