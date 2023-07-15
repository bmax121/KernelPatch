#ifndef _KP_TASKEXT_H_
#define _KP_TASKEXT_H_

// #include <linux/sched.h>
// #include <linux/sched/task.h>

struct task_struct;

typedef struct task_ext
{
} task_ext;

static inline struct task_ext *get_task_ext(struct task_struct *task)
{
}

#endif
