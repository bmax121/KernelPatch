// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * syscall 45 (truncate) is repurposed as the KP supercall channel
 * (user/uapi/scdefs.h: __NR_supercall). Authentication is manager-based: the
 * caller's uid must match the trusted APatch manager appid. Anything else
 * passes through to the original sys_truncate unchanged.
 */
#include "supercall.h"
#include "dispatch.h"

#include <linux/cred.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/user_namespace.h>
#include "scdefs.h"

#include "../include/kp_lkm.h"
#include "../infra/syscall_table.h"
#include "../manager/manager.h"
#include "sucompat.h"

#define KP_SUPERCALL_NR 45 /* __NR3264_truncate */

static kp_syscall_fn_t kp_orig_truncate;

static long kp_supercall_handler(const struct pt_regs *regs)
{
	uid_t uid = from_kuid(current_user_ns(), current_uid());

	/* The manager may grant/revoke allowlist entries; an already-allowed uid
	 * may use the SU supercalls. Anything else is a plain truncate() call. */
	if (!kp_is_manager_uid(uid) && !kp_is_su_allow_uid(uid)) {
		logkd("supercall: uid %u not authorized (manager?%d allow?%d)\n", uid,
		      kp_is_manager_uid(uid), kp_is_su_allow_uid(uid));
		if (kp_orig_truncate)
			return kp_orig_truncate(regs);
		return -ENOSYS;
	}

	long ver_xx_cmd = regs->regs[1];
	long cmd = ver_xx_cmd & 0xFFFF;
	if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) {
		logkd("bad supercall cmd 0x%lx\n", cmd);
		return kp_orig_truncate ? kp_orig_truncate(regs) : -EINVAL;
	}

	return kp_handle_supercall(cmd, regs->regs[2], regs->regs[3], regs->regs[4], regs->regs[5]);
}

int kp_supercall_install(void)
{
	int rc = kp_syscall_hook(KP_SUPERCALL_NR, kp_supercall_handler, &kp_orig_truncate);
	if (rc)
		return rc;
	logki("supercall installed on syscall %d\n", KP_SUPERCALL_NR);
	return 0;
}

void kp_supercall_uninstall(void)
{
	kp_syscall_unhook(KP_SUPERCALL_NR, kp_orig_truncate);
	kp_orig_truncate = NULL;
}
