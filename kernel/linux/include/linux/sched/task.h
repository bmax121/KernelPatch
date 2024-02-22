#ifndef _LINUX_SCHED_TASK_H
#define _LINUX_SCHED_TASK_H

#include <ktypes.h>
#include <ksyms.h>
#include <linux/init_task.h>

struct task_struct;
struct rusage;
union thread_union;
struct css_set;
struct kernel_clone_args;

extern rwlock_t *kvar(tasklist_lock);
extern spinlock_t *kvar(mmlist_lock);

extern void kfunc_def(__put_task_struct)(struct task_struct *t);
extern int kfunc_def(lockdep_tasklist_lock_is_held)(void);
extern asmlinkage void kfunc_def(schedule_tail)(struct task_struct *prev);
extern void kfunc_def(init_idle)(struct task_struct *idle, int cpu);
extern int kfunc_def(sched_fork)(unsigned long clone_flags, struct task_struct *p);
extern void kfunc_def(sched_cgroup_fork)(struct task_struct *p, struct kernel_clone_args *kargs);
extern void kfunc_def(sched_post_fork)(struct task_struct *p);
extern void kfunc_def(sched_dead)(struct task_struct *p);
extern void __noreturn kfunc_def(do_task_dead)(void);
extern void __noreturn kfunc_def(make_task_dead)(int signr);
extern void kfunc_def(proc_caches_init)(void);
extern void kfunc_def(fork_init)(void);
extern void kfunc_def(release_task)(struct task_struct *p);
// extern int kfunc_def(copy_thread)(struct task_struct *, const struct kernel_clone_args *);
extern int kfunc_def(copy_thread)(unsigned long clone_flags, unsigned long stack_start, unsigned long stk_sz,
                                  struct task_struct *p, unsigned long tls);
extern void kfunc_def(flush_thread)(void);
extern void kfunc_def(exit_thread)(struct task_struct *tsk);
extern __noreturn void kfunc_def(do_group_exit)(int);
extern void kfunc_def(exit_files)(struct task_struct *);
extern void kfunc_def(exit_itimers)(struct task_struct *);
extern pid_t kfunc_def(kernel_clone)(struct kernel_clone_args *kargs);
extern struct task_struct *kfunc_def(create_io_thread)(int (*fn)(void *), void *arg, int node);
extern struct task_struct *kfunc_def(fork_idle)(int);
extern struct mm_struct *kfunc_def(copy_init_mm)(void);
extern pid_t kfunc_def(kernel_thread)(int (*fn)(void *), void *arg, unsigned long flags);
extern pid_t kfunc_def(user_mode_thread)(int (*fn)(void *), void *arg, unsigned long flags);
extern int kfunc_def(kernel_wait)(pid_t pid, int *stat);
extern void kfunc_def(free_task)(struct task_struct *tsk);
extern void kfunc_def(sched_exec)(void);

static inline void __put_task_struct(struct task_struct *t)
{
    kfunc_direct_call(__put_task_struct, t);
}

static inline int lockdep_tasklist_lock_is_held(void)
{
    kfunc_call(lockdep_tasklist_lock_is_held);
    kfunc_not_found();
    return 0;
}

static inline asmlinkage void schedule_tail(struct task_struct *prev)
{
    kfunc_call(schedule_tail, prev);
    kfunc_not_found();
}

static inline void init_idle(struct task_struct *idle, int cpu)
{
    kfunc_call(init_idle, idle, cpu);
    kfunc_not_found();
}

static inline int sched_fork(unsigned long clone_flags, struct task_struct *p)
{
    kfunc_call(sched_fork, clone_flags, p);
    kfunc_not_found();
    return 0;
}

static inline void sched_cgroup_fork(struct task_struct *p, struct kernel_clone_args *kargs)
{
    kfunc_call(sched_cgroup_fork, p, kargs);
    kfunc_not_found();
}

static inline void sched_post_fork(struct task_struct *p)
{
    kfunc_call(sched_post_fork, p);
    kfunc_not_found();
}

static inline void sched_dead(struct task_struct *p)
{
    kfunc_call(sched_dead, p);
    kfunc_not_found();
}

static inline void __noreturn do_task_dead(void)
{
    kfunc_call_void(do_task_dead);
    kfunc_not_found();
}

static inline void __noreturn make_task_dead(int signr)
{
    kfunc_call_void(make_task_dead, signr);
    kfunc_not_found();
}

static inline void proc_caches_init(void)
{
    kfunc_call(proc_caches_init);
    kfunc_not_found();
}

static inline void fork_init(void)
{
    kfunc_call(fork_init);
    kfunc_not_found();
}

static inline void release_task(struct task_struct *p)
{
    kfunc_call(release_task, p);
    kfunc_not_found();
}

static inline int copy_thread(unsigned long clone_flags, unsigned long stack_start, unsigned long stk_sz,
                              struct task_struct *p, unsigned long tls)
{
    kfunc_call(copy_thread, clone_flags, stack_start, stk_sz, p, tls);
    kfunc_not_found();
    return 0;
}

static inline void flush_thread(void)
{
    kfunc_call(flush_thread);
    kfunc_not_found();
}
static inline void exit_thread(struct task_struct *tsk)
{
    kfunc_call(exit_thread, tsk);
    kfunc_not_found();
}
static inline __noreturn void do_group_exit(int exit_code)
{
    kfunc_call_void(do_group_exit, exit_code);
    kfunc_not_found();
}
static inline void exit_files(struct task_struct *tsk)
{
    kfunc_call(exit_files, tsk);
    kfunc_not_found();
}
static inline void exit_itimers(struct task_struct *tsk)
{
    kfunc_call(exit_itimers, tsk);
    kfunc_not_found();
}
static inline pid_t kernel_clone(struct kernel_clone_args *kargs)
{
    kfunc_call(kernel_clone, kargs);
    kfunc_not_found();
    return 0;
}
static inline struct task_struct *create_io_thread(int (*fn)(void *), void *arg, int node)
{
    kfunc_call(create_io_thread, fn, arg, node);
    kfunc_not_found();
    return 0;
}
static inline struct task_struct *fork_idle(int cpu)
{
    kfunc_call(fork_idle, cpu);
    kfunc_not_found();
    return 0;
}
static inline struct mm_struct *copy_init_mm(void)
{
    kfunc_call(copy_init_mm);
    kfunc_not_found();
    return 0;
}
static inline pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
    kfunc_call(kernel_thread, fn, arg, flags);
    kfunc_not_found();
    return 0;
}
static inline pid_t user_mode_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
    kfunc_call(user_mode_thread, fn, arg, flags);
    kfunc_not_found();
    return 0;
}
static inline int kernel_wait(pid_t pid, int *stat)
{
    kfunc_call(kernel_wait, pid, stat);
    kfunc_not_found();
    return 0;
}
static inline void free_task(struct task_struct *tsk)
{
    kfunc_call(free_task, tsk);
    kfunc_not_found();
}
static inline void sched_exec(void)
{
    kfunc_call(sched_exec);
    kfunc_not_found();
}

#endif