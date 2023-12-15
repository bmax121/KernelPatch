/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/processor.h
 *
 * Copyright (C) 1995-1999 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_PROCESSOR_H
#define __ASM_PROCESSOR_H

#include <asm/current.h>
#include <asm/ptrace.h>

#define task_stack_page(task) (get_stack(task))

// #define THREAD_SIZE 16384
// #define THREAD_START_SP (THREAD_SIZE - 16)
// #define task_pt_regs(p) ((struct pt_regs *)(THREAD_START_SP + task_stack_page(p)) - 1)

static inline struct pt_regs *_task_pt_reg(struct task_struct *task)
{
    unsigned long stack = (unsigned long)task_stack_page(task);
    uintptr_t addr = (uintptr_t)(thread_size + stack);
    if (kver < VERSION(4, 4, 19)) {
        // todo: fault on 3.18 ranch-27
        addr -= 16;
        addr -= sizeof(struct pt_regs_lt4419);
    } else if (kver < VERSION(4, 14, 0)) {
        addr -= 16;
        addr -= sizeof(struct pt_regs_lt4140);
    } else if (kver < VERSION(5, 10, 0)) {
        addr -= sizeof(struct pt_regs_lt5100);
    } else {
        addr -= sizeof(struct pt_regs);
    }
    struct pt_regs *regs;
    regs = (struct pt_regs *)(addr);
    return regs;
}

#define task_pt_regs(p) _task_pt_reg(p)

#endif