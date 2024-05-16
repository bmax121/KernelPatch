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

extern char all_allow_sctx[SUPERCALL_SCONTEXT_LEN];
extern int allow_sid_enable;
extern uint32_t all_allow_sid;

int set_all_allow_sctx(const char *sctx);
int commit_kernel_su();
int commit_common_su(uid_t to_uid, const char *sctx);
int commit_su(uid_t uid, const char *sctx);
int task_su(pid_t pid, uid_t to_uid, const char *sctx);

int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext, int async);
int su_remove_allow_uid(uid_t uid, int async);
int su_allow_uid_nums();
int su_allow_uids(int is_user, uid_t *out_uids, int out_num);
int su_allow_uid_profile(int is_user, uid_t uid, struct su_profile *profile);
int su_reset_path(const char *path);
const char *su_get_path();

/**
 * @brief Whether to make the current task bypass all selinux permission checks.
 * 
 * @param task 
 * @param val 
 */
static inline void set_priv_sel_allow(struct task_struct *task, bool val)
{
    struct task_ext *ext = get_task_ext(task);
    ext->priv_sel_allow = val;
    dsb(ish);
}

#endif