#ifndef __ASM_CURRENT_H
#define __ASM_CURRENT_H

#include <compiler.h>

struct task_struct;

// CONFIG_THREAD_INFO_IN_TASK or >= 4.10.0
static __always_inline struct task_struct *get_current(void)
{
    unsigned long sp_el0;
    asm("mrs %0, sp_el0" : "=r"(sp_el0));
    return (struct task_struct *)sp_el0;
}

// current_thread_info()->task;

#define current get_current()

#endif