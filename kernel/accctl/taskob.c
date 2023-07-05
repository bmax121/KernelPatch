#include "accctl.h"

#include <kallsyms.h>
#include <hook.h>

#include <asm/current.h>
#include <linux/sched/task.h>
#include <linux/pid.h>

void before_do_exit(hook_fdata2_t *data, void *udata)
{
    struct task_struct *task = current;
    if (is_white_task(task)) {
        // pid_t pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        // pid_t tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
        del_white_task(task);
    }
}

void after_copy_process(hook_fdata8_t *data, void *udata)
{
    struct task_struct *task = current;
    if (is_white_task(task)) {
        struct task_struct *new = (struct task_struct *)data->ret;
        // pid_t ppid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        // pid_t tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
        // pid_t pid = __task_pid_nr_ns(new, PIDTYPE_PID, 0);
        add_white_task(new);
    }
}

int task_observer()
{
    unsigned long do_exit_addr = kallsyms_lookup_name("do_exit");
    hook_wrap2((void *)do_exit_addr, before_do_exit, 0, 0, 0);
    unsigned long copy_process_addr = kallsyms_lookup_name("copy_process");
    hook_wrap8((void *)copy_process_addr, 0, after_copy_process, 0, 0);
    return 0;
}