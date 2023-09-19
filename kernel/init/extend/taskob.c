#include <taskob.h>
#include <taskext.h>
#include <kallsyms.h>
#include <hook.h>
#include <asm/current.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <minc/string.h>
#include <error.h>
#include <pgtable.h>

static inline void prepare_init_ext(struct task_struct *task)
{
    struct task_ext *ext = get_task_ext(task);
    ext->magic = TASK_EXT_MAGIC;
    ext->task = task;
    ext->pid = 0;
    ext->tgid = 0;
    ext->super = false;
    ext->selinux_allow = false;
    dsb(ish);
    isb();
}

static inline void prepare_task_ext(struct task_struct *new, struct task_struct *old)
{
    struct task_ext *new_ext = get_task_ext(new);
    struct task_ext *old_ext = get_task_ext(old);
    new_ext->magic = TASK_EXT_MAGIC;
    new_ext->task = new;
    new_ext->pid = __task_pid_nr_ns(new, PIDTYPE_PID, 0);
    new_ext->tgid = __task_pid_nr_ns(new, PIDTYPE_TGID, 0);
    new_ext->super = false;
    new_ext->selinux_allow = old_ext->selinux_allow;
}

static struct task_struct *(*backup_copy_process)(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6,
                                                  void *a7) = 0;

struct task_struct *replace_copy_process(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    dsb(ish);
    isb();
    struct task_struct *new = backup_copy_process(a0, a1, a2, a3, a4, a5, a6, a7);
    prepare_task_ext(new, current);
    dsb(ish);
    isb();
    return new;
}

static void (*backup_cgroup_post_fork)(struct task_struct *p, void *_1) = 0;

void replace_cgroup_post_fork(struct task_struct *p, void *_1)
{
    struct task_struct *new = p;
    dsb(sy);
    isb();
    backup_cgroup_post_fork(p, _1);
    prepare_task_ext(new, current);
    dsb(ish);
    isb();
}

int task_observer()
{
    prepare_init_ext(kvar(init_task));

    unsigned long copy_process_addr = kallsyms_lookup_name("copy_process");
    if (copy_process_addr) {
        hook((void *)copy_process_addr, (void *)replace_copy_process, (void **)&backup_copy_process);
    } else {
        logkw("Can't find local symbol copy_process, try cgroup_post_fork");
        unsigned long cgroup_post_fork_addr = kallsyms_lookup_name("cgroup_post_fork");
        if (!cgroup_post_fork_addr) {
            logke("Can't find symbol cgroup_post_fork\n");
            return ERR_NO_SUCH_SYMBOL;
        }
        hook((void *)cgroup_post_fork_addr, (void *)replace_cgroup_post_fork, (void **)&backup_cgroup_post_fork);
    }

    return 0;
}