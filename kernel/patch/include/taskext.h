/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_TASKEXT_H_
#define _KP_TASKEXT_H_

#include <asm/current.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <stdbool.h>
#include <linux/err.h>

#define TASK_EXT_MAGIC 0x11581158

/// @brief  the size of current struct task_ext, not included _magic
extern int task_ext_size;

/**
 * @brief An extension of task_struct, stored in the kernel thread stack, 
 * can be used to store task-local(thread-local) variables. 
 * This can be very useful if you need to pass thread-local variables across multiple hook points.
 * 
 * Task-local variables can be dynamically expanded.
 * @see reg_task_local
 * @see has_task_local
 * @see task_local_ptr
 */
struct task_ext
{
    // first
    int size;
    pid_t pid;
    pid_t tgid;
    bool root;
    bool sel_allow;
    bool priv_sel_allow;
    // last
    int _magic;
};

/**
 * @brief Is task_ext dirty, and is it available?
 * 
 * @param ext 
 * @return int 
 */
static inline bool task_ext_valid(struct task_ext *ext)
{
    return !IS_ERR(ext) && (*(int *)(ext->size + (uintptr_t)ext) == TASK_EXT_MAGIC);
}

/**
 * @brief Register a new task-local varilable
 * 
 * @param size The size of task-local varilable
 * @return The offset of of task-local varilable, 
 * This value is needed when access this task-local variable.
 * 
 * @see has_task_local
 * @see task_local_ptr
 */
static inline int reg_task_local(int size)
{
    int offset = task_ext_size;
    offset += size;
    return offset;
}

/**
 * @brief Is there a task-local variable regiseted?
 * 
 * @param ext
 * @param offset Return value of reg_task_local
 * @return true 
 * @return false 
 * 
 * @see reg_task_local
 */
static inline bool has_task_local(struct task_ext *ext, int offset)
{
    return offset >= ext->size;
}

/**
 * @brief Access task-local varilable, 
 * 
 * @param offset Return value of reg_task_local
 * @return void* Task-local varilable pointer
 * 
 * @see reg_task_local
 */
static inline void *task_local_ptr(struct task_ext *ext, int offset)
{
    return (void *)((uintptr_t)ext + offset);
}

#endif
