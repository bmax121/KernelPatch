#ifndef _KP_TASKEXT_H_
#define _KP_TASKEXT_H_

#include <asm/current.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

#define TASK_EXT_MAGIC 0x1158115811581158

struct task_ext
{
    // first
    struct task_struct *task;
    pid_t pid;
    pid_t tgid;
    bool selinux_allow;
    // last
    uint64_t magic;
};

static inline bool task_ext_valid(struct task_ext *ext)
{
    bool rc = ext->magic == TASK_EXT_MAGIC;
    return rc;
}

#endif
