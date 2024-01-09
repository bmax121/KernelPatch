/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_TASKEXT_H_
#define _KP_TASKEXT_H_

#include <asm/current.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

#define TASK_EXT_MAGIC 0x1158115811581158

struct task_ext
{
    // first
    pid_t pid;
    pid_t tgid;
    int super;
    int _;
    int selinux_allow;
    int priv_selinux_allow;
    void *__;
    // last
    uint64_t magic;
};

static inline int task_ext_valid(struct task_ext *ext)
{
    return ext && (ext->magic == TASK_EXT_MAGIC);
}

#endif
