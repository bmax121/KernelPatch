#ifndef __ASM_CURRENT_H
#define __ASM_CURRENT_H

#include <stdint.h>
#include <stdbool.h>
#include <compiler.h>
#include <pgtable.h>

struct task_struct;

extern int thread_size;
extern bool thread_info_in_task;
extern bool task_is_sp_el0;
extern bool thread_info_is_sp_el0;
extern bool thread_info_is_sp;
extern int task_in_thread_info_offset;
extern int stack_in_task_offset;
extern int stack_end_offset;

register uint64_t current_stack_pointer asm("sp");

static __always_inline struct thread_info *legacy_current_thread_info_sp()
{
    return (struct thread_info *)(current_stack_pointer & ~(thread_size - 1));
}

static __always_inline struct thread_info *legacy_current_thread_info_sp_el0()
{
    uint64_t sp_el0;
    asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
    return (struct thread_info *)sp_el0;
}

static inline struct thread_info *current_thread_info()
{
    if (likely(task_is_sp_el0)) {
        uint64_t sp_el0;
        asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
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

static inline struct task_struct *get_current()
{
    if (likely(task_is_sp_el0)) {
        uint64_t sp_el0;
        asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
        return (struct task_struct *)sp_el0;
    }
    uint64_t addr = (uint64_t)current_thread_info() + task_in_thread_info_offset;
    return *(struct task_struct **)addr;
}

#define current get_current()

static inline void *get_stack(struct task_struct *task)
{
    uint64_t addr = (uint64_t)task + stack_in_task_offset;
    return (void *)*(uint64_t *)addr;
}

static inline void *get_current_stack()
{
    return get_stack(current);
}

static inline struct task_ext *get_task_ext(struct task_struct *task)
{
    uint64_t addr = (uint64_t)get_stack(task);
    addr += stack_end_offset;
    return (struct task_ext *)(addr);
}

static inline struct task_ext *get_current_task_ext()
{
    return get_task_ext(current);
}

#define current_ext get_current_task_ext()

static inline const struct task_struct *override_current(struct task_struct *task)
{
    if (task_is_sp_el0) {
        uint64_t sp_el0;
        asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
        asm volatile("msr sp_el0, %0" ::"r"(task));
        return (struct task_struct *)sp_el0;
    }
    uint64_t addr = (uint64_t)current_thread_info() + task_in_thread_info_offset;
    struct task_struct *old = *(struct task_struct **)addr;
    *(struct task_struct **)addr = (struct task_struct *)task;
    return old;
}

static inline void revert_current(const struct task_struct *old)
{
    if (task_is_sp_el0) {
        asm volatile("msr sp_el0, %0" ::"r"(old));
        return;
    }
    uint64_t addr = (uint64_t)current_thread_info() + task_in_thread_info_offset;
    *(struct task_struct **)addr = (struct task_struct *)old;
}

#endif