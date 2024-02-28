/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <taskob.h>
#include <taskext.h>
#include <kallsyms.h>
#include <hook.h>
#include <asm/current.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <log.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <pgtable.h>
#include <linux/fs.h>
#include <linux/seccomp.h>
#include <baselib.h>
#include <uapi/asm-generic/errno.h>
#include <predata.h>

static inline void prepare_init_ext(struct task_struct *task)
{
    struct task_ext *ext = get_task_ext(task);
    for (uintptr_t i = (uintptr_t)ext; i < (uintptr_t)ext + sizeof(struct task_ext); i += 8) {
        *(uintptr_t *)i = 0;
    }
    ext->magic = TASK_EXT_MAGIC;
}

static void prepare_task_ext(struct task_struct *new, struct task_struct *old)
{
    struct task_ext *old_ext = get_task_ext(old);
    if (unlikely(!task_ext_valid(old_ext))) {
        logkfe("dirty task_ext, pid(maybe dirty): %d\n", old_ext->pid);
        return;
    }
    struct task_ext *new_ext = get_task_ext(new);
    for (uintptr_t i = (uintptr_t)new_ext; i < (uintptr_t)new_ext + sizeof(struct task_ext); i += 8) {
        *(uintptr_t *)i = 0;
    }
    new_ext->magic = TASK_EXT_MAGIC;

    new_ext->pid = __task_pid_nr_ns(new, PIDTYPE_PID, 0);
    new_ext->tgid = __task_pid_nr_ns(new, PIDTYPE_TGID, 0);
    new_ext->selinux_allow = old_ext->selinux_allow;

    dsb(ishst);
}

static struct task_struct *(*backup_copy_process)(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6,
                                                  void *a7) = 0;

struct task_struct *replace_copy_process(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    struct task_struct *new = backup_copy_process(a0, a1, a2, a3, a4, a5, a6, a7);
    if (unlikely(!new || IS_ERR(new))) return new;
    prepare_task_ext(new, current);
    return new;
}

static void (*backup_cgroup_post_fork)(struct task_struct *p, void *a1) = 0;

static void replace_cgroup_post_fork(struct task_struct *p, void *a1)
{
    struct task_struct *new = p;
    backup_cgroup_post_fork(p, a1);
    prepare_task_ext(new, current);
}

int task_observer()
{
    int rc = 0;

    prepare_init_ext(init_task);

    // __switch_to
    unsigned long copy_process_addr = get_preset_patch_sym()->copy_process;
    if (copy_process_addr) {
        hook_err_t err = hook((void *)copy_process_addr, (void *)replace_copy_process, (void **)&backup_copy_process);
        if (err) {
            log_boot("hook copy_process: %llx, error: %d\n", copy_process_addr, err);
            rc = err;
            goto out;
        }
    } else {
        log_boot("no symbol copy_process, try cgroup_post_fork\n");
        unsigned long cgroup_post_fork_addr = get_preset_patch_sym()->cgroup_post_fork;
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

out:
    return rc;
}