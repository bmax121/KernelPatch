/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PTRACE_H
#define _LINUX_PTRACE_H

#include <asm/current.h>
#include <asm/processor.h>
#include <asm/ptrace.h>

#define current_pt_regs() task_pt_regs(current)

#define current_user_stack_pointer() user_stack_pointer(current_pt_regs())

#endif