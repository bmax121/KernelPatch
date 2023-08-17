#include <taskob.h>
#include <taskext.h>
#include <kallsyms.h>
#include <hook.h>
#include <asm/current.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <minc/string.h>

static inline void prepare_init_ext(struct task_struct *task)
{
    struct task_ext *ext = get_task_ext(task);
    ext->magic = TASK_EXT_MAGIC;
    ext->task = task;
    ext->pid = 0;
    ext->tgid = 0;
    ext->selinux_allow = false;
}

static inline struct task_ext *prepare_task_ext(struct task_struct *new, struct task_struct *old)
{
    struct task_ext *new_ext = get_task_ext(new);
    struct task_ext *old_ext = get_task_ext(old);

    new_ext->magic = TASK_EXT_MAGIC;
    new_ext->task = new;
    new_ext->pid = __task_pid_nr_ns(new, PIDTYPE_PID, 0);
    new_ext->tgid = __task_pid_nr_ns(new, PIDTYPE_TGID, 0);
    new_ext->selinux_allow = false;

    //
    if (old_ext->selinux_allow) {
        new_ext->selinux_allow = true;
    }

#if 0
    u32 new_secid = 0, seclen = 0;
    const char *new_secctx = 0;
    security_task_getsecid(new, &new_secid);
    security_secid_to_secctx(new_secid, &new_secctx, &seclen);
    if (new_secctx)
        security_release_secctx(new_secctx, seclen);
#endif

    return new_ext;
}

void before_do_exit(hook_fdata2_t *data, void *udata)
{
}

void after_copy_process(hook_fdata8_t *data, void *udata)
{
    struct task_struct *old = current;
    struct task_ext *old_ext = get_task_ext(old);
    old_ext = old_ext;

    struct task_struct *new = (struct task_struct *)data->ret;
    struct task_ext *new_ext = prepare_task_ext(new, old);
    new_ext = new_ext;
}

int task_observer()
{
    prepare_init_ext(kvar(init_task));

    unsigned long do_exit_addr = kallsyms_lookup_name("do_exit");
    hook_wrap2((void *)do_exit_addr, before_do_exit, 0, 0, 0);

    unsigned long copy_process_addr = kallsyms_lookup_name("copy_process");
    hook_wrap8((void *)copy_process_addr, 0, after_copy_process, 0, 0);
    return 0;
}