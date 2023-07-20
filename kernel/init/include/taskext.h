#ifndef _KP_TASKEXT_H_
#define _KP_TASKEXT_H_

#include <asm/current.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

#define TASK_EXT_MAGIC 0x11581158
#define TASK_EXT_EMAGIC 0x11581158

#define EXT_SELINUX_PERM_ALL 0xffffffff

struct task_ext
{
    uint32_t magic;
    struct task_struct *task;
    uint32_t lsm_perm;
    uint32_t selinux_perm;
    uint32_t emagic;
};

static inline bool task_ext_valid(struct task_ext *ext)
{
    return ext->magic == TASK_EXT_MAGIC && ext->emagic == TASK_EXT_EMAGIC;
}

struct task_ext *prepare_task_ext(struct task_struct *task);

#endif
