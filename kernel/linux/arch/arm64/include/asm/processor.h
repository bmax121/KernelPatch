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

// implemented in utils

extern int16_t pt_regs_offset;

struct pt_regs *_task_pt_reg(struct task_struct *task);

#define task_pt_regs(p) _task_pt_reg(p)

#endif