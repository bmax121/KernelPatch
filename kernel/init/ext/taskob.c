#include <taskext.h>
#include <kallsyms.h>
#include <hook.h>
#include <asm/current.h>
#include <linux/sched/task.h>
#include <linux/pid.h>

// static void log_task_debug(struct task_struct *task)
// {
//     pid_t pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
//     pid_t tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
//     pid_t ppid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
//     logkd("task: %llx, pid: %d, tgid: %d, ppid: %d\n", task, pid, tgid, ppid);
// }

void before_do_exit(hook_fdata2_t *data, void *udata)
{
}

void after_copy_process(hook_fdata8_t *data, void *udata)
{
    struct task_struct *task = current;
    struct task_ext *ext = get_task_ext(task);

    struct task_struct *new = (struct task_struct *)data->ret;
    struct task_ext *new_ext = prepare_task_ext(new);

    if (!task_ext_valid(ext)) return;

    new_ext->selinux_perm = ext->selinux_perm;
}

int task_observer()
{
    prepare_task_ext(kvar(init_task));

    unsigned long do_exit_addr = kallsyms_lookup_name("do_exit");
    hook_wrap2((void *)do_exit_addr, before_do_exit, 0, 0, 0);
    unsigned long copy_process_addr = kallsyms_lookup_name("copy_process");
    hook_wrap8((void *)copy_process_addr, 0, after_copy_process, 0, 0);
    return 0;
}