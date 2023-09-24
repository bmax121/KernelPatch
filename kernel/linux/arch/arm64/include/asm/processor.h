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

#define task_stack_page(task) (get_stack(task))

#define task_pt_regs(p) ((struct pt_regs *)(thread_size + task_stack_page(p)) - 1)

#endif