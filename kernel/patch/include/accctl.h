/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_ACCCTL_H_
#define _KP_ACCCTL_H_

#include <ktypes.h>
#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <pgtable.h>
#include <taskext.h>
#include <asm/current.h>

#include <uapi/asm-generic/errno.h>

#ifndef CONFIG_KP_NO_ROOT
extern char all_allow_sctx[SUPERCALL_SCONTEXT_LEN];
extern uint32_t all_allow_sid;

int set_all_allow_sctx(const char *sctx);
int commit_kernel_su();
int commit_common_su(uid_t to_uid, const char *sctx);
int commit_su(uid_t uid, const char *sctx);
int task_su(pid_t pid, uid_t to_uid, const char *sctx);
#else
static inline int set_all_allow_sctx(const char *sctx) { (void)sctx; return -ENOSYS; }
static inline int commit_kernel_su(void) { return -ENOSYS; }
static inline int commit_common_su(uid_t to_uid, const char *sctx) { (void)to_uid; (void)sctx; return -ENOSYS; }
static inline int commit_su(uid_t uid, const char *sctx) { (void)uid; (void)sctx; return -ENOSYS; }
static inline int task_su(pid_t pid, uid_t to_uid, const char *sctx) { (void)pid; (void)to_uid; (void)sctx; return -ENOSYS; }
#endif /* CONFIG_KP_NO_ROOT */

int bypass_selinux(void);
#if defined(CONFIG_KP_NO_ROOT) && defined(CONFIG_KP_NO_OFFICIAL_MANAGER)
void unhook_bypass_selinux(void);
#endif

/**
 * @brief Whether to make the current task bypass all selinux permission checks.
 * 
 * @param task 
 * @param val 
 */
static inline void set_priv_sel_allow(struct task_struct *task, bool val)
{
    struct task_ext *ext = kf_task_ext_ensure(task);
    if (!ext) return;
    ext->priv_sel_allow = val;
    dsb(ish);
}

#endif