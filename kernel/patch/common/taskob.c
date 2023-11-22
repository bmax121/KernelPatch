#include <taskob.h>
#include <taskext.h>
#include <kallsyms.h>
#include <hook.h>
#include <asm/current.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <minc/string.h>
#include <log.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <pgtable.h>
#include <linux/fs.h>
#include <uapi/asm-generic/errno.h>

static inline void prepare_init_ext(struct task_struct *task)
{
    struct task_ext *ext = get_task_ext(task);
    ext->magic = TASK_EXT_MAGIC;
    ext->pid = 0;
    ext->tgid = 0;
    ext->super = 0;
    ext->selinux_allow = 0;
}

static void prepare_task_ext(struct task_struct *new, struct task_struct *old)
{
    struct task_ext *old_ext = get_task_ext(old);
    if (unlikely(!task_ext_valid(old_ext))) {
        logkfe("dirty task_ext, pid(maybe dirty): %d\n", old_ext->pid);
        return;
    }
    struct task_ext *new_ext = get_task_ext(new);
    new_ext->magic = TASK_EXT_MAGIC;

    new_ext->pid = __task_pid_nr_ns(new, PIDTYPE_PID, 0);
    new_ext->tgid = __task_pid_nr_ns(new, PIDTYPE_TGID, 0);
    new_ext->super = 0;
    new_ext->selinux_allow = old_ext->selinux_allow;

    dsb(ishst);
}

static struct task_struct *(*backup_copy_process)(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6,
                                                  void *a7) = 0;

struct task_struct *replace_copy_process(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    struct task_struct *new = backup_copy_process(a0, a1, a2, a3, a4, a5, a6, a7);
    if (unlikely(IS_ERR_VALUE(new))) return new;
    prepare_task_ext(new, current);
    return new;
}

static void (*backup_cgroup_post_fork)(struct task_struct *p, void *a1) = 0;

void replace_cgroup_post_fork(struct task_struct *p, void *a1)
{
    struct task_struct *new = p;
    backup_cgroup_post_fork(p, a1);
    prepare_task_ext(new, current);
}

unsigned long execv_hook_addr = 0;

static int hook_execv_compat(void *data, const char *name, struct module *, unsigned long addr)
{
    if (min_strncmp("do_execve_common", name, min_strlen("do_execve_common"))) {
        return 0;
    }
    execv_hook_addr = addr;
    return 1;
}

// int do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
// int __do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags,
//                      struct file *file);
// static int do_execve_common(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp)
hook_err_t add_execv_hook(hook_chain8_callback before, hook_chain8_callback after, void *udata)
{
    return hook_wrap8((void *)execv_hook_addr, before, after, udata);
}

void remove_execv_hook(hook_chain8_callback before, hook_chain8_callback after)
{
    hook_unwrap((void *)execv_hook_addr, before, after);
}

int task_observer()
{
    int rc = 0;

    prepare_init_ext(kvar(init_task));

    unsigned long copy_process_addr = kallsyms_lookup_name("copy_process");
    if (copy_process_addr) {
        hook_err_t err = hook((void *)copy_process_addr, (void *)replace_copy_process, (void **)&backup_copy_process);
        if (err) {
            log_boot("hook copy_process: %llx, error: %d\n", copy_process_addr, err);
            rc = err;
            goto out;
        }
    } else {
        log_boot("no symbol copy_process, try cgroup_post_fork\n");
        unsigned long cgroup_post_fork_addr = kallsyms_lookup_name("cgroup_post_fork");
        if (!cgroup_post_fork_addr) {
            log_boot("no symbol cgroup_post_fork\n");
            rc = -ENOENT;
            goto out;
        }
        hook_err_t err =
            hook((void *)cgroup_post_fork_addr, (void *)replace_cgroup_post_fork, (void **)&backup_cgroup_post_fork);
        if (err != HOOK_NO_ERR) {
            log_boot("hook cgroup_post_fork: %llx, error: %d\n", cgroup_post_fork_addr, err);
            rc = err;
            goto out;
        }
    }

    // hook execv
    execv_hook_addr = kallsyms_lookup_name("__do_execve_file");
    if (!execv_hook_addr) execv_hook_addr = kallsyms_lookup_name("do_execveat_common");
    if (!execv_hook_addr) {
        kallsyms_on_each_symbol(hook_execv_compat, 0);
    }

    if (!execv_hook_addr) {
        log_boot("no symbol for execv hook\n");
        rc = -ENOENT;
        goto out;
    } else {
        hook_err_t err = hook_wrap8((void *)execv_hook_addr, 0, 0, 0);
        if (err) {
            log_boot("hook execv: %llx, error: %d\n", execv_hook_addr, err);
            rc = err;
            goto out;
        }
    }

out:
    return rc;
}