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
#include <symbol.h>

static inline void prepare_init_ext(struct task_struct *task)
{
    struct task_ext *ext = get_task_ext(task);
    for (uintptr_t i = (uintptr_t)ext; i < (uintptr_t)ext + sizeof(struct task_ext); i += 8) {
        *(uintptr_t *)i = 0;
    }
    ext->size = task_ext_size;
    ext->_magic = TASK_EXT_MAGIC;
    dsb(ish);
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
    new_ext->size = task_ext_size;
    new_ext->_magic = TASK_EXT_MAGIC;

    new_ext->pid = __task_pid_nr_ns(new, PIDTYPE_PID, 0);
    new_ext->tgid = __task_pid_nr_ns(new, PIDTYPE_TGID, 0);
    new_ext->sel_allow = old_ext->sel_allow;

    dsb(ish);
}

int task_ext_size = offsetof(struct task_ext, _magic);
KP_EXPORT_SYMBOL(task_ext_size);

static void after_copy_process(hook_fargs8_t *args, void *udata)
{
    struct task_struct *new = (struct task_struct *)args->ret;
    if (unlikely(!new || IS_ERR(new))) return;
    prepare_task_ext(new, current);
}

static void after_cgroup_post_fork(hook_fargs4_t *args, void *udata)
{
    struct task_struct *new = (struct task_struct *)args->arg0;
    prepare_task_ext(new, current);
}

int task_observer()
{
    int rc = 0;

    prepare_init_ext(init_task);

    unsigned long copy_process_addr = get_preset_patch_sym()->copy_process;
    if (copy_process_addr) {
        rc |= hook_wrap8((void *)copy_process_addr, 0, after_copy_process, 0);
        log_boot("hook copy_process: %llx, rc: %d\n", copy_process_addr, rc);
    } else {
        unsigned long cgroup_post_fork_addr = get_preset_patch_sym()->cgroup_post_fork;
        if (cgroup_post_fork_addr) {
            rc |= hook_wrap4((void *)cgroup_post_fork_addr, 0, after_cgroup_post_fork, 0);
            log_boot("hook cgroup_post_fork: %llx, rc: %d\n", cgroup_post_fork_addr, rc);
        } else {
            rc = HOOK_BAD_ADDRESS;
        }
    }

    return rc;
}