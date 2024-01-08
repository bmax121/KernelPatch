#ifndef _LINUX_PID_H
#define _LINUX_PID_H

#include <ktypes.h>
#include <ksyms.h>

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

struct upid;
struct pid;
struct file;
struct pid_namespace;
struct task_struct;

extern struct pid init_struct_pid;
extern const struct file_operations pidfd_fops;
extern struct pid_namespace init_pid_ns;
extern int pid_max;
extern int pid_max_min, pid_max_max;

extern struct pid *kfunc_def(pidfd_pid)(const struct file *file); // fork.c
extern struct pid *kfunc_def(pidfd_get_pid)(unsigned int fd, unsigned int *flags);
extern void kfunc_def(put_pid)(struct pid *pid);
extern struct task_struct *kfunc_def(pid_task)(struct pid *pid, enum pid_type);
extern struct task_struct *kfunc_def(get_pid_task)(struct pid *pid, enum pid_type);
extern struct pid *kfunc_def(get_task_pid)(struct task_struct *task, enum pid_type type);
extern void kfunc_def(attach_pid)(struct task_struct *task, enum pid_type);
extern void kfunc_def(detach_pid)(struct task_struct *task, enum pid_type);
extern void kfunc_def(change_pid)(struct task_struct *task, enum pid_type, struct pid *pid);
extern void kfunc_def(exchange_tids)(struct task_struct *task, struct task_struct *old);
extern void kfunc_def(transfer_pid)(struct task_struct *old, struct task_struct *new, enum pid_type);

extern struct pid *kfunc_def(find_pid_ns)(int nr, struct pid_namespace *ns);
extern struct pid *kfunc_def(find_vpid)(int nr);
extern struct pid *kfunc_def(find_get_pid)(int nr);
extern struct pid *kfunc_def(find_ge_pid)(int nr, struct pid_namespace *ns);
extern struct pid *kfunc_def(alloc_pid)(struct pid_namespace *ns, pid_t *set_tid, size_t set_tid_size);
extern void kfunc_def(free_pid)(struct pid *pid);
extern void kfunc_def(disable_pid_allocation)(struct pid_namespace *ns);
extern pid_t kfunc_def(pid_nr_ns)(struct pid *pid, struct pid_namespace *ns);
extern pid_t kfunc_def(pid_vnr)(struct pid *pid);

static inline struct pid *pidfd_get_pid(unsigned int fd, unsigned int *flags)
{
    kfunc_call(pidfd_get_pid, fd, flags);
    kfunc_not_found();
    return 0;
}
static inline void put_pid(struct pid *pid)
{
    kfunc_call(put_pid, pid);
    kfunc_not_found();
}
static inline struct task_struct *pid_task(struct pid *pid, enum pid_type type)
{
    kfunc_call(pid_task, pid, type);
    kfunc_not_found();
    return 0;
}
static inline struct task_struct *get_pid_task(struct pid *pid, enum pid_type type)
{
    kfunc_call(get_pid_task, pid, type);
    kfunc_not_found();
    return 0;
}
static inline struct pid *get_task_pid(struct task_struct *task, enum pid_type type)
{
    kfunc_call(get_task_pid, task, type);
    kfunc_not_found();
    return 0;
}
static inline void attach_pid(struct task_struct *task, enum pid_type type)
{
    kfunc_call(attach_pid, task, type);
    kfunc_not_found();
}
static inline void detach_pid(struct task_struct *task, enum pid_type type)
{
    kfunc_call(detach_pid, task, type);
    kfunc_not_found();
}
static inline void change_pid(struct task_struct *task, enum pid_type type, struct pid *pid)
{
    kfunc_call(change_pid, task, type, pid);
    kfunc_not_found();
}
static inline void exchange_tids(struct task_struct *task, struct task_struct *old)
{
    kfunc_call(exchange_tids, task, old);
    kfunc_not_found();
}
static inline void transfer_pid(struct task_struct *old, struct task_struct *new, enum pid_type type)
{
    kfunc_call(transfer_pid, old, new, type);
    kfunc_not_found();
}

static inline struct pid *find_pid_ns(int nr, struct pid_namespace *ns)
{
    kfunc_direct_call(find_pid_ns, nr, ns);
}

static inline struct pid *find_vpid(int nr)
{
    kfunc_direct_call(find_vpid, nr);
}

static inline struct pid *find_get_pid(int nr)
{
    kfunc_direct_call(find_get_pid, nr);
}

static inline struct pid *find_ge_pid(int nr, struct pid_namespace *ns)
{
    kfunc_direct_call(find_ge_pid, nr, ns);
}

static inline struct pid *alloc_pid(struct pid_namespace *ns, pid_t *set_tid, size_t set_tid_size)
{
    kfunc_direct_call(alloc_pid, ns, set_tid, set_tid_size);
}

static inline void free_pid(struct pid *pid)
{
    kfunc_direct_call(free_pid, pid);
}

static inline void disable_pid_allocation(struct pid_namespace *ns)
{
    kfunc_call(disable_pid_allocation, ns);
    kfunc_not_found();
}

static inline pid_t pid_nr_ns(struct pid *pid, struct pid_namespace *ns)
{
    kfunc_call(pid_nr_ns, pid, ns);
    kfunc_not_found();
    return 0;
}
static inline pid_t pid_vnr(struct pid *pid)
{
    kfunc_call(pid_vnr, pid);
    kfunc_not_found();
    return 0;
}

#endif /* _LINUX_PID_H */