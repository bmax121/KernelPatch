#ifndef _KP_ACCCTL_H_
#define _KP_ACCCTL_H_

#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

#define MAX_WHITE_PID_NUM 15
#define MAX_WHITE_TASK_NUM 127

#define ACC_INHERIT (1 << 0)

#define ERR_ACCCTL_WHITE_FULL -1
#define ERR_ACCCTL_NO_SUCH_ID -2

extern struct task_struct *white_tasks[];
// extern uint32_t tasks_flag[];

int lsm_hook_install();
int selinux_hook_install();
int acccss_control_init();

static inline bool is_white_task(struct task_struct *task)
{
    for (int i = 0; i < MAX_WHITE_TASK_NUM; i++) {
        struct task_struct *t = white_tasks[i];
        if (!t) return false;
        if (t == task) return true;
    }
    return false;
}

int add_white_task(struct task_struct *task);
void del_white_task(struct task_struct *task);

int commit_su_nodep();
int commit_su();
int grant_su(pid_t vpid, bool real);

#endif