#ifndef __LINUX_STACKTRACE_H
#define __LINUX_STACKTRACE_H

#include <ksyms.h>

struct pt_regs;

struct stack_trace
{
    unsigned int nr_entries, max_entries;
    unsigned long *entries;
    int skip; /* input argument: How many entries to skip */
};

extern void kfunc_def(save_stack_trace)(struct stack_trace *trace);
extern void kfunc_def(save_stack_trace_regs)(struct pt_regs *regs, struct stack_trace *trace);
extern void kfunc_def(save_stack_trace_tsk)(struct task_struct *tsk, struct stack_trace *trace);
extern void kfunc_def(print_stack_trace)(struct stack_trace *trace, int spaces);
extern void kfunc_def(save_stack_trace_user)(struct stack_trace *trace);

static inline void save_stack_trace(struct stack_trace *trace)
{
    kfunc_call_void(save_stack_trace, trace);
    kfunc_not_found()
}

static inline void save_stack_trace_regs(struct pt_regs *regs, struct stack_trace *trace)
{
    kfunc_call_void(save_stack_trace_regs, regs, trace);
    kfunc_not_found()
}

static inline void save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
{
    kfunc_call_void(save_stack_trace_tsk, tsk, trace);
    kfunc_not_found()
}

static inline void print_stack_trace(struct stack_trace *trace, int spaces)
{
    kfunc_call_void(print_stack_trace, trace, spaces);
    kfunc_not_found()
}

static inline void save_stack_trace_user(struct stack_trace *trace)
{
    kfunc_call_void(save_stack_trace_user, trace);
    kfunc_not_found()
}

#endif