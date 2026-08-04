/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * sys_call_table locator + entry patch/restore. KP reuses syscall 45
 * (truncate) as the supercall channel (see user/uapi/scdefs.h: __NR_supercall).
 * We overwrite sys_call_table[45] with our handler and save the original so
 * non-supercall truncate calls pass through unchanged.
 */
#ifndef _KP_LKM_SYSCALL_TABLE_H_
#define _KP_LKM_SYSCALL_TABLE_H_
#include <linux/ptrace.h>
#include <linux/types.h>

typedef long (*kp_syscall_fn_t)(const struct pt_regs *regs);

/* Resolve sys_call_table. Returns 0 on success. */
int kp_syscall_table_init(void);

/* Patch sys_call_table[nr] with @fn, store the original in *@orig. */
int kp_syscall_hook(int nr, kp_syscall_fn_t fn, kp_syscall_fn_t *orig);

/* Restore sys_call_table[nr] to @orig. */
void kp_syscall_unhook(int nr, kp_syscall_fn_t orig);

/* Resolved table address (NULL until kp_syscall_table_init succeeds). */
extern kp_syscall_fn_t *kp_sys_call_table;

#endif /* _KP_LKM_SYSCALL_TABLE_H_ */
