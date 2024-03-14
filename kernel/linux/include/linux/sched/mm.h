/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_MM_H
#define _LINUX_SCHED_MM_H

#include <ktypes.h>
#include <ksyms.h>

/* mmput gets rid of the mappings and all user-space */
extern void kfunc_def(mmput)(struct mm_struct *);

/* same as above but performs the slow path from the async context. Can
 * be called from the atomic context as well
 */
extern void kfunc_def(mmput_async)(struct mm_struct *);

/* Grab a reference to a task's mm, if it is not already going away */
extern struct mm_struct *kfunc_def(get_task_mm)(struct task_struct *task);

static inline void mmput(struct mm_struct *mm)
{
    kfunc_direct_call_void(mmput, mm);
}

static inline void mmput_async(struct mm_struct *mm)
{
    kfunc_direct_call_void(mmput_async, mm);
}

static inline struct mm_struct *get_task_mm(struct task_struct *task)
{
    kfunc_direct_call(get_task_mm, task);
}

#endif