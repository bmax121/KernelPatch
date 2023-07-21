#ifndef _KP_TASKEXT_H_
#define _KP_TASKEXT_H_

#include <asm/current.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

#define TASK_EXT_MAGIC 0x11581158
#define EXT_SELINUX_PERM_ALL 0xffffffff

struct task_ext
{
    // first
    struct task_struct *task;
    uint32_t lsm_perm;
    uint32_t selinux_perm;
    // last
    uint32_t magic;
};

static inline bool task_ext_valid(struct task_ext *ext)
{
    bool ret = ext->magic == TASK_EXT_MAGIC;
    if (!ret) {
        // todo: crash
        logke("invalid task_ext: %llx, task(dirty): %llx\n", ext, ext->task);
    }
    return ret;
}

static inline struct task_ext *prepare_task_ext(struct task_struct *task)
{
    struct task_ext *ext = get_task_ext(task);
    ext->task = task;
    ext->lsm_perm = 0;
    ext->selinux_perm = 0;
    ext->magic = TASK_EXT_MAGIC;
    return ext;
}

#endif
