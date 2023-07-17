#ifndef __ASM_CURRENT_H
#define __ASM_CURRENT_H

#include <stdint.h>
#include <stdbool.h>
#include <compiler.h>

struct task_struct;

extern int thread_size;
extern bool thread_info_in_task;
extern bool task_is_sp_el0;
extern bool thread_info_is_sp_el0;
extern bool thread_info_is_sp;
extern int task_in_thread_info_offset;
extern int stack_in_task_offset;

#define KP_THREAD_INFO_MAX_SIZE 0x80

register unsigned long current_stack_pointer asm("sp");

static __always_inline struct thread_info *legacy_current_thread_info_sp()
{
    return (struct thread_info *)(current_stack_pointer & ~(thread_size - 1));
}

static __always_inline struct thread_info *legacy_current_thread_info_sp_el0()
{
    unsigned long sp_el0;
    asm("mrs %0, sp_el0" : "=r"(sp_el0));
    return (struct thread_info *)sp_el0;
}

static __always_inline struct thread_info *current_thread_info()
{
    if (task_is_sp_el0) {
        unsigned long sp_el0;
        asm("mrs %0, sp_el0" : "=r"(sp_el0));
        if (thread_info_in_task) {
            return (struct thread_info *)sp_el0;
        } else {
            return *(struct thread_info **)(sp_el0 + stack_in_task_offset);
        }
    }
    struct thread_info *ti = legacy_current_thread_info_sp_el0();
    if (thread_info_is_sp) ti = legacy_current_thread_info_sp();
    return ti;
}

static __always_inline struct task_struct *get_current()
{
    if (task_is_sp_el0) {
        unsigned long sp_el0;
        asm("mrs %0, sp_el0" : "=r"(sp_el0));
        return (struct task_struct *)sp_el0;
    }
    uintptr_t addr = (uintptr_t)current_thread_info() + task_in_thread_info_offset;
    return *(struct task_struct **)addr;
}

#define current get_current()

static __always_inline void *get_stack(struct task_struct *task)
{
    uintptr_t addr = (uintptr_t)task + stack_in_task_offset;
    return (void *)*(uintptr_t *)addr;
}

static __always_inline void *get_current_stack()
{
    return get_stack(current);
}

static __always_inline struct task_ext *get_task_ext(struct task_struct *task)
{
    uintptr_t addr = (uintptr_t)get_stack(task);
    if (thread_info_in_task) return (void *)addr;
    return (void *)(addr + KP_THREAD_INFO_MAX_SIZE);
}

static __always_inline struct task_ext *get_current_task_ext()
{
    return get_task_ext(current);
}

#define current_ext get_current_task_ext()

static inline const struct task_struct *override_current(struct task_struct *task)
{
    if (task_is_sp_el0) {
        unsigned long sp_el0;
        asm("mrs %0, sp_el0" : "=r"(sp_el0));
        asm("msr sp_el0, %0" ::"r"(task));
        return (struct task_struct *)sp_el0;
    }
    uintptr_t addr = (uintptr_t)current_thread_info() + task_in_thread_info_offset;
    struct task_struct *old = *(struct task_struct **)addr;
    *(struct task_struct **)addr = (struct task_struct *)task;
    return old;
}

static inline void revert_current(const struct task_struct *old)
{
    if (task_is_sp_el0) {
        asm("msr sp_el0, %0" ::"r"(old));
        return;
    }
    uintptr_t addr = (uintptr_t)current_thread_info() + task_in_thread_info_offset;
    *(struct task_struct **)addr = (struct task_struct *)old;
}

#endif