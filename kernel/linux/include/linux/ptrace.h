/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PTRACE_H
#define _LINUX_PTRACE_H

#include <asm/current.h>
#include <asm/processor.h>

#ifndef current_pt_regs
#define current_pt_regs() task_pt_regs(current)
#endif

#define user_mode(regs) (((regs)->pstate & PSR_MODE_MASK) == PSR_MODE_EL0t)

#define compat_user_mode(regs) (((regs)->pstate & (PSR_MODE32_BIT | PSR_MODE_MASK)) == (PSR_MODE32_BIT | PSR_MODE_EL0t))

// #define user_stack_pointer(regs) (!compat_user_mode(regs) ? (regs)->sp : (regs)->compat_sp)
#define user_stack_pointer(regs) ((regs)->sp)

#ifndef current_user_stack_pointer
#define current_user_stack_pointer() user_stack_pointer(current_pt_regs())
#endif

#endif