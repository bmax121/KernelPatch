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

int commit_su_nodep()
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

int commit_su()
{
    int rc = 0;
    struct task_struct *task = current;
    struct task_ext *ext = get_task_ext(task);
    if (!task_ext_valid(ext)) {
        logkfe("dirty task_ext pid(maybe dirty): %d\n", ext->pid);
        rc = ERR_DIRTY_EXT;
        goto out;
    }

    ext->super = true;
    ext->selinux_allow = true;

    struct cred *new = prepare_creds();

    if (cred_offset.cap_inheritable_offset >= 0)
        *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_inheritable_offset) = full_cap;
    if (cred_offset.cap_permitted_offset >= 0)
        *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_permitted_offset) = full_cap;
    if (cred_offset.cap_effective_offset >= 0)
        *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_effective_offset) = full_cap;
    if (cred_offset.cap_bset_offset >= 0)
        *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_bset_offset) = full_cap;
    if (cred_offset.cap_ambient_offset >= 0)
        *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_ambient_offset) = full_cap;

    if (cred_offset.uid_offset >= 0)
        *(uid_t *)((uintptr_t) new + cred_offset.uid_offset) = 0;
    if (cred_offset.euid_offset >= 0)
        *(uid_t *)((uintptr_t) new + cred_offset.euid_offset) = 0;
    if (cred_offset.fsuid_offset >= 0)
        *(uid_t *)((uintptr_t) new + cred_offset.fsuid_offset) = 0;
    if (cred_offset.suid_offset >= 0)
        *(uid_t *)((uintptr_t) new + cred_offset.suid_offset) = 0;

    if (cred_offset.gid_offset >= 0)
        *(uid_t *)((uintptr_t) new + cred_offset.gid_offset) = 0;
    if (cred_offset.egid_offset >= 0)
        *(uid_t *)((uintptr_t) new + cred_offset.egid_offset) = 0;
    if (cred_offset.fsgid_offset >= 0)
        *(uid_t *)((uintptr_t) new + cred_offset.fsgid_offset) = 0;
    if (cred_offset.sgid_offset >= 0)
        *(uid_t *)((uintptr_t) new + cred_offset.sgid_offset) = 0;

    commit_creds(new);

    // logkd("commit_su  pid:   %d, tgid: %d\n", ext->pid, ext->tgid);
    logkd("commit_su pid: %d\n", ext->pid);
out:
    return rc;
}

// todo: cow
int thread_su(pid_t vpid, bool real)
{
    int rc = 0;
    struct task_struct *task = find_get_task_by_vpid(vpid);
    if (!task) {
        rc = ERR_NO_SUCH_ID;
        goto out;
    }
    struct task_ext *ext = get_task_ext(task);

    if (!task_ext_valid(ext)) {
        logkfe("dirty task_ext pid(maybe dirty): %d\n", ext->pid);
        rc = ERR_DIRTY_EXT;
        goto out;
    }

    ext->selinux_allow = true;

    // todo: COW
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);

    if (cred_offset.cap_inheritable_offset >= 0)
        *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_inheritable_offset) = full_cap;
    if (cred_offset.cap_permitted_offset >= 0)
        *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_permitted_offset) = full_cap;
    if (cred_offset.cap_effective_offset >= 0)
        *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_effective_offset) = full_cap;
    if (cred_offset.cap_bset_offset >= 0)
        *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_bset_offset) = full_cap;
    if (cred_offset.cap_ambient_offset >= 0)
        *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_ambient_offset) = full_cap;

    if (cred_offset.uid_offset >= 0)
        *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset) = 0;
    if (cred_offset.euid_offset >= 0)
        *(uid_t *)((uintptr_t)cred + cred_offset.euid_offset) = 0;
    if (cred_offset.fsuid_offset >= 0)
        *(uid_t *)((uintptr_t)cred + cred_offset.fsuid_offset) = 0;
    if (cred_offset.suid_offset >= 0)
        *(uid_t *)((uintptr_t)cred + cred_offset.suid_offset) = 0;

    if (cred_offset.gid_offset >= 0)
        *(uid_t *)((uintptr_t)cred + cred_offset.gid_offset) = 0;
    if (cred_offset.egid_offset >= 0)
        *(uid_t *)((uintptr_t)cred + cred_offset.egid_offset) = 0;
    if (cred_offset.fsgid_offset >= 0)
        *(uid_t *)((uintptr_t)cred + cred_offset.fsgid_offset) = 0;
    if (cred_offset.sgid_offset >= 0)
        *(uid_t *)((uintptr_t)cred + cred_offset.sgid_offset) = 0;

    if (real) {
        struct cred *real_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset);

        if (cred_offset.cap_inheritable_offset >= 0)
            *(kernel_cap_t *)((uintptr_t)real_cred + cred_offset.cap_inheritable_offset) = full_cap;
        if (cred_offset.cap_permitted_offset >= 0)
            *(kernel_cap_t *)((uintptr_t)real_cred + cred_offset.cap_permitted_offset) = full_cap;
        if (cred_offset.cap_effective_offset >= 0)
            *(kernel_cap_t *)((uintptr_t)real_cred + cred_offset.cap_effective_offset) = full_cap;
        if (cred_offset.cap_bset_offset >= 0)
            *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_bset_offset) = full_cap;
        if (cred_offset.cap_ambient_offset >= 0)
            *(kernel_cap_t *)((uintptr_t)real_cred + cred_offset.cap_ambient_offset) = full_cap;

        if (cred_offset.uid_offset >= 0)
            *(uid_t *)((uintptr_t)real_cred + cred_offset.uid_offset) = 0;
        if (cred_offset.euid_offset >= 0)
            *(uid_t *)((uintptr_t)real_cred + cred_offset.euid_offset) = 0;
        if (cred_offset.fsuid_offset >= 0)
            *(uid_t *)((uintptr_t)real_cred + cred_offset.fsuid_offset) = 0;
        if (cred_offset.suid_offset >= 0)
            *(uid_t *)((uintptr_t)real_cred + cred_offset.suid_offset) = 0;

        if (cred_offset.gid_offset >= 0)
            *(uid_t *)((uintptr_t)real_cred + cred_offset.gid_offset) = 0;
        if (cred_offset.egid_offset >= 0)
            *(uid_t *)((uintptr_t)real_cred + cred_offset.egid_offset) = 0;
        if (cred_offset.fsgid_offset >= 0)
            *(uid_t *)((uintptr_t)real_cred + cred_offset.fsgid_offset) = 0;
        if (cred_offset.sgid_offset >= 0)
            *(uid_t *)((uintptr_t)real_cred + cred_offset.sgid_offset) = 0;
    }
    // logkd("thread_su pid: %d, tgid: %d\n", ext->pid, ext->tgid);
    logkd("commit_su pid: %d\n", ext->pid);
out:
    __put_task_struct(task);
    return rc;
}
