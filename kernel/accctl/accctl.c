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

struct task_struct *white_tasks[MAX_WHITE_TASK_NUM + 1] = { 0 };
DEFINE_SPINLOCK(white_task_lock);

// todo:
int add_white_task(struct task_struct *task)
{
    if (!task) return 0;
    unsigned long flags = spin_lock_irqsave(&white_task_lock);
    int ret = ERR_ACCCTL_WHITE_FULL;
    int i;
    for (i = 0; i < MAX_WHITE_PID_NUM; i++) {
        struct task_struct *t = white_tasks[i];
        if (!t || t == task || (t == white_tasks[i + 1])) {
            white_tasks[i] = task;
            ret = 0;
            break;
        }
    }
    spin_unlock_irqrestore(&white_task_lock, flags);

    pid_t tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    pid_t pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
    logkd("add_white_task: tgid: %d, pid: %d, ret: %d\n", tgid, pid, ret);
    return ret;
}

void del_white_task(struct task_struct *task)
{
    if (!task) return;
    unsigned long flags = spin_lock_irqsave(&white_task_lock);
    for (int i = MAX_WHITE_PID_NUM - 1; i >= 0; i--) {
        if (white_tasks[i] == task) white_tasks[i] = white_tasks[i + 1];
    }
    spin_unlock_irqrestore(&white_task_lock, flags);

    pid_t tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    pid_t pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
    logkd("del_white_task: tgid: %d, pid: %d\n", tgid, pid);
}

// todo: test
int commit_su_nodep()
{
    int ret = 0;
    struct task_struct *task = current;
    struct task_ext *ext = get_task_ext(task);
    if (!task_ext_valid(ext)) goto out;

    ext->selinux_perm = EXT_SELINUX_PERM_ALL;

    const struct cred *old = get_task_cred(task);
    struct cred *new = prepare_kernel_cred(0);
    u32 secid;
    if (kfunc_def(security_cred_getsecid)) {
        kfunc_def(security_cred_getsecid)(old, &secid);
        set_security_override(new, secid);
    }
    commit_creds(new);
out:
    return ret;
}

int commit_su()
{
    int ret = 0;
    struct task_struct *task = current;
    struct task_ext *ext = get_task_ext(task);
    if (!task_ext_valid(ext)) goto out;

    ext->selinux_perm = EXT_SELINUX_PERM_ALL;

    struct cred *new = prepare_creds();

    if (cred_offset.cap_inheritable_offset >= 0)
        *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_inheritable_offset) = full_cap;
    if (cred_offset.cap_permitted_offset >= 0)
        *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_permitted_offset) = full_cap;
    if (cred_offset.cap_effective_offset >= 0)
        *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_effective_offset) = full_cap;
    if (cred_offset.cap_bset_offset >= 0) *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_bset_offset) = full_cap;
    if (cred_offset.cap_ambient_offset >= 0)
        *(kernel_cap_t *)((uintptr_t) new + cred_offset.cap_ambient_offset) = full_cap;

    if (cred_offset.uid_offset >= 0) *(uid_t *)((uintptr_t) new + cred_offset.uid_offset) = 0;
    if (cred_offset.euid_offset >= 0) *(uid_t *)((uintptr_t) new + cred_offset.euid_offset) = 0;
    if (cred_offset.fsuid_offset >= 0) *(uid_t *)((uintptr_t) new + cred_offset.fsuid_offset) = 0;
    if (cred_offset.suid_offset >= 0) *(uid_t *)((uintptr_t) new + cred_offset.suid_offset) = 0;

    if (cred_offset.gid_offset >= 0) *(uid_t *)((uintptr_t) new + cred_offset.gid_offset) = 0;
    if (cred_offset.egid_offset >= 0) *(uid_t *)((uintptr_t) new + cred_offset.egid_offset) = 0;
    if (cred_offset.fsgid_offset >= 0) *(uid_t *)((uintptr_t) new + cred_offset.fsgid_offset) = 0;
    if (cred_offset.sgid_offset >= 0) *(uid_t *)((uintptr_t) new + cred_offset.sgid_offset) = 0;

    commit_creds(new);

    pid_t tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    pid_t pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
    logkd("commit_su: tgid: %d, pid: %d, ret: %d\n", tgid, pid, ret);

out:
    return ret;
}

// todo: cow
int grant_su(pid_t vpid, bool real)
{
    int ret = 0;
    struct pid *pid_struct = find_get_pid(vpid);
    if (!pid_struct) {
        ret = ERR_ACCCTL_NO_SUCH_ID;
        goto out;
    }
    struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        ret = ERR_ACCCTL_NO_SUCH_ID;
        goto out;
    }
    struct task_ext *ext = get_task_ext(task);
    if (!task_ext_valid(ext)) goto out;

    ext->selinux_perm = EXT_SELINUX_PERM_ALL;

    logkd("pid: %d grant_su, task: %llx, ext: %llx\n", vpid, task, ext);

    // todo: COW
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);

    if (cred_offset.cap_inheritable_offset >= 0)
        *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_inheritable_offset) = full_cap;
    if (cred_offset.cap_permitted_offset >= 0)
        *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_permitted_offset) = full_cap;
    if (cred_offset.cap_effective_offset >= 0)
        *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_effective_offset) = full_cap;
    if (cred_offset.cap_bset_offset >= 0) *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_bset_offset) = full_cap;
    if (cred_offset.cap_ambient_offset >= 0)
        *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_ambient_offset) = full_cap;

    if (cred_offset.uid_offset >= 0) *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset) = 0;
    if (cred_offset.euid_offset >= 0) *(uid_t *)((uintptr_t)cred + cred_offset.euid_offset) = 0;
    if (cred_offset.fsuid_offset >= 0) *(uid_t *)((uintptr_t)cred + cred_offset.fsuid_offset) = 0;
    if (cred_offset.suid_offset >= 0) *(uid_t *)((uintptr_t)cred + cred_offset.suid_offset) = 0;

    if (cred_offset.gid_offset >= 0) *(uid_t *)((uintptr_t)cred + cred_offset.gid_offset) = 0;
    if (cred_offset.egid_offset >= 0) *(uid_t *)((uintptr_t)cred + cred_offset.egid_offset) = 0;
    if (cred_offset.fsgid_offset >= 0) *(uid_t *)((uintptr_t)cred + cred_offset.fsgid_offset) = 0;
    if (cred_offset.sgid_offset >= 0) *(uid_t *)((uintptr_t)cred + cred_offset.sgid_offset) = 0;

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

        if (cred_offset.uid_offset >= 0) *(uid_t *)((uintptr_t)real_cred + cred_offset.uid_offset) = 0;
        if (cred_offset.euid_offset >= 0) *(uid_t *)((uintptr_t)real_cred + cred_offset.euid_offset) = 0;
        if (cred_offset.fsuid_offset >= 0) *(uid_t *)((uintptr_t)real_cred + cred_offset.fsuid_offset) = 0;
        if (cred_offset.suid_offset >= 0) *(uid_t *)((uintptr_t)real_cred + cred_offset.suid_offset) = 0;

        if (cred_offset.gid_offset >= 0) *(uid_t *)((uintptr_t)real_cred + cred_offset.gid_offset) = 0;
        if (cred_offset.egid_offset >= 0) *(uid_t *)((uintptr_t)real_cred + cred_offset.egid_offset) = 0;
        if (cred_offset.fsgid_offset >= 0) *(uid_t *)((uintptr_t)real_cred + cred_offset.fsgid_offset) = 0;
        if (cred_offset.sgid_offset >= 0) *(uid_t *)((uintptr_t)real_cred + cred_offset.sgid_offset) = 0;
    }

    // free:
    put_pid(pid_struct);
    // __put_task_struct(task);
out:
    return ret;
}

// for debug
void _log_current_whites()
{
    for (int i = 0; i < MAX_WHITE_TASK_NUM; i++) {
        struct task_struct *task = white_tasks[i];
        if (!task) return;
        pid_t pid = task_pid_vnr(task);
        logkd("---- pid: %d\n", pid);
    }
}

int acccss_control_init()
{
#if 0
    lsm_hook_install();
#endif
    selinux_hook_install();
    supercall_init();
    return 0;
}
