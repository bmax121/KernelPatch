#ifndef _LINUX_SECCOMP_H
#define _LINUX_SECCOMP_H

#include <ksyms.h>
#include <ktypes.h>
#include <uapi/linux/seccomp.h>

struct seccomp_filter;
/**
 * struct seccomp - the state of a seccomp'ed process
 *
 * @mode:  indicates one of the valid values above for controlled
 *         system calls available to a process.
 * @filter: must always point to a valid seccomp-filter or NULL as it is
 *          accessed without locking during system call entry.
 *
 *          @filter must only be accessed from the context of current as there
 *          is no read locking.
 */
struct seccomp
{
    int mode;
    atomic_t filter_count;
    struct seccomp_filter *filter;
};

// struct seccomp
// {
//     int mode;
//     struct seccomp_filter *filter;
// };

extern long kfunc_def(prctl_get_seccomp)(void);
extern long kfunc_def(prctl_set_seccomp)(unsigned long seccomp_mode, char __user *filter);

extern void kfunc_def(put_seccomp_filter)(struct task_struct *tsk);
extern void kfunc_def(get_seccomp_filter)(struct task_struct *tsk);

// #ifdef CONFIG_SECCOMP_FILTER
extern void kfunc_def(seccomp_filter_release)(struct task_struct *tsk);
extern void kfunc_def(get_seccomp_filter)(struct task_struct *tsk);
// #else /* CONFIG_SECCOMP_FILTER */

static inline long prctl_get_seccomp(void)
{
    kfunc_direct_call(prctl_get_seccomp);
}

static inline long prctl_set_seccomp(unsigned long seccomp_mode, char __user *filter)
{
    kfunc_direct_call(prctl_set_seccomp, seccomp_mode, filter);
}

static inline void put_seccomp_filter(struct task_struct *tsk)
{
    kfunc_direct_call(put_seccomp_filter, tsk);
}

static inline void get_seccomp_filter(struct task_struct *tsk)
{
    kfunc_direct_call(get_seccomp_filter, tsk);
}

static inline void seccomp_filter_release(struct task_struct *tsk)
{
    kfunc_call_void(seccomp_filter_release, tsk);
}

#endif