#ifndef __ASM_CURRENT_H
#define __ASM_CURRENT_H

#include <stdint.h>
#include <stdbool.h>
#include <compiler.h>
#include <pgtable.h>

struct task_struct;

#define THREAD_SIZE 16384

extern int thread_size;
extern int thread_info_in_task;
extern int sp_el0_is_current;
extern int sp_el0_is_thread_info;
extern int task_in_thread_info_offset;
extern int stack_in_task_offset;
extern int stack_end_offset;

register uint64_t current_stack_pointer asm("sp");

static __always_inline struct thread_info *current_thread_info_sp()
{
    return (struct thread_info *)(current_stack_pointer & ~(thread_size - 1));
}

static inline uint64_t current_sp_el0()
{
    uint64_t sp_el0;
    asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
    return sp_el0;
}

static inline struct thread_info *current_thread_info_sp_el0()
{
    return (struct thread_info *)current_sp_el0;
}

static inline struct thread_info *current_thread_info()
{
    if (thread_info_in_task || sp_el0_is_thread_info) return (struct thread_info *)current_sp_el0();
    return current_thread_info_sp();
}

static inline struct task_struct *get_current()
{
    if (likely(sp_el0_is_current)) {
        uint64_t sp_el0;
        asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
        return (struct task_struct *)sp_el0;
    }
    uint64_t addr = (uint64_t)current_thread_info() + task_in_thread_info_offset;
    return *(struct task_struct **)addr;
}
#define current get_current()

static inline unsigned long *get_stack(const struct task_struct *task)
{
    uint64_t addr = (uint64_t)task + stack_in_task_offset;
    return *(unsigned long **)addr;
}

static inline unsigned long *end_of_stack(const struct task_struct *task)
{
    unsigned long sp_end = (unsigned long)get_stack(task);
    sp_end = sp_end + stack_end_offset;
    return (unsigned long *)sp_end;
}

static inline unsigned long *get_current_stack()
{
    return get_stack(current);
}

static inline struct task_ext *get_task_ext(const struct task_struct *task)
{
    return (struct task_ext *)(end_of_stack(task) + 1);
}

static inline struct task_ext *get_current_task_ext()
{
    return get_task_ext(current);
}

static inline struct thread_info *get_task_thread_info(const struct task_struct *task)
{
    if (thread_info_in_task) return (struct thread_info *)task;
    return (struct thread_info *)get_stack(task);
}

#define current_ext get_current_task_ext()

static inline const struct task_struct *override_current(struct task_struct *task)
{
    if (sp_el0_is_current) {
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
    if (sp_el0_is_current) {
        asm volatile("msr sp_el0, %0" ::"r"(old));
        return;
    }
    uint64_t addr = (uint64_t)current_thread_info() + task_in_thread_info_offset;
    *(struct task_struct **)addr = (struct task_struct *)old;
}

#endif