#include "accctl.h"

#include <taskext.h>
#include <linux/spinlock.h>
#include <linux/capability.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/sched.h>
#include <pgtable.h>
#include <ksyms.h>
#include <error.h>

int commit_kernel_cred()
{
    int rc = 0;
    struct task_struct *task = current;
    struct task_ext *ext = get_task_ext(task);
    if (!task_ext_valid(ext))
        goto out;

    const struct cred *old = get_task_cred(task);
    struct cred *new = prepare_kernel_cred(0);
    u32 secid;
    if (kfunc_def(security_cred_getsecid)) {
        kfunc_def(security_cred_getsecid)(old, &secid);
        set_security_override(new, secid);
    }
    commit_creds(new);
out:
    return rc;
}

int commit_su(int super, const char *sctx)
{
    int rc = 0;
    struct task_struct *task = current;
    struct task_ext *ext = get_task_ext(task);
    if (!task_ext_valid(ext)) {
        logkfe("dirty task_ext, pid(maybe dirty): %d\n", ext->pid);
        rc = ERR_DIRTY_EXT;
        goto out;
    }

    ext->super = super;
    ext->selinux_allow = 1;

    struct cred *new = prepare_creds();

    *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_inheritable_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_permitted_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_effective_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_bset_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_ambient_offset) = full_cap;

    *(uid_t *)((uintptr_t) new + cred_offset.uid_offset) = 0;
    *(uid_t *)((uintptr_t) new + cred_offset.euid_offset) = 0;
    *(uid_t *)((uintptr_t) new + cred_offset.fsuid_offset) = 0;
    *(uid_t *)((uintptr_t) new + cred_offset.suid_offset) = 0;

    *(uid_t *)((uintptr_t) new + cred_offset.gid_offset) = 0;
    *(uid_t *)((uintptr_t) new + cred_offset.egid_offset) = 0;
    *(uid_t *)((uintptr_t) new + cred_offset.fsgid_offset) = 0;
    *(uid_t *)((uintptr_t) new + cred_offset.sgid_offset) = 0;

    if (sctx) {
        rc = set_security_override_from_ctx(new, sctx);
        if (rc) {
            logkfw("set sctx: %s error: %d\n", sctx, rc);
            goto out;
        }
    }

    commit_creds(new);

    ext->selinux_allow = !sctx;

    logkfd("pid: %d, tgid: %d\n", ext->pid, ext->tgid);
out:
    return rc;
}

// todo: cow, rcu
int thread_su(pid_t vpid, const char *sctx)
{
    int rc = 0;
    struct task_struct *task = find_get_task_by_vpid(vpid);
    if (!task) {
        rc = ERR_NO_SUCH_ID;
        goto out;
    }
    struct task_ext *ext = get_task_ext(task);

    if (!task_ext_valid(ext)) {
        logkfe("dirty task_ext, pid(maybe dirty): %d\n", ext->pid);
        rc = ERR_DIRTY_EXT;
        goto out;
    }

    ext->selinux_allow = 1;

    // cred
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);

    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_inheritable_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_permitted_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_effective_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_bset_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_ambient_offset) = full_cap;

    *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset) = 0;
    *(uid_t *)((uintptr_t)cred + cred_offset.euid_offset) = 0;
    *(uid_t *)((uintptr_t)cred + cred_offset.fsuid_offset) = 0;
    *(uid_t *)((uintptr_t)cred + cred_offset.suid_offset) = 0;

    *(uid_t *)((uintptr_t)cred + cred_offset.gid_offset) = 0;
    *(uid_t *)((uintptr_t)cred + cred_offset.egid_offset) = 0;
    *(uid_t *)((uintptr_t)cred + cred_offset.fsgid_offset) = 0;
    *(uid_t *)((uintptr_t)cred + cred_offset.sgid_offset) = 0;

    // real_cred
    struct cred *real_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset);

    *(kernel_cap_t *)((uintptr_t)real_cred + cred_offset.cap_inheritable_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)real_cred + cred_offset.cap_permitted_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)real_cred + cred_offset.cap_effective_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_bset_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)real_cred + cred_offset.cap_ambient_offset) = full_cap;

    *(uid_t *)((uintptr_t)real_cred + cred_offset.uid_offset) = 0;
    *(uid_t *)((uintptr_t)real_cred + cred_offset.euid_offset) = 0;
    *(uid_t *)((uintptr_t)real_cred + cred_offset.fsuid_offset) = 0;
    *(uid_t *)((uintptr_t)real_cred + cred_offset.suid_offset) = 0;

    *(uid_t *)((uintptr_t)real_cred + cred_offset.gid_offset) = 0;
    *(uid_t *)((uintptr_t)real_cred + cred_offset.egid_offset) = 0;
    *(uid_t *)((uintptr_t)real_cred + cred_offset.fsgid_offset) = 0;
    *(uid_t *)((uintptr_t)real_cred + cred_offset.sgid_offset) = 0;

    if (sctx) {
        rc = set_security_override_from_ctx(cred, sctx);
        rc = set_security_override_from_ctx(real_cred, sctx);
        if (rc) {
            logkfw("set sctx: %s error: %d", sctx, rc);
            goto out;
        }
    }

    ext->selinux_allow = !sctx;

    logkfd("pid: %d, tgid: %d\n", ext->pid, ext->tgid);
out:
    __put_task_struct(task);
    return rc;
}
