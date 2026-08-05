// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Supercall command dispatch. ABI matches user/uapi/scdefs.h.
 */
#include "dispatch.h"
#include "su.h"

#include <linux/errno.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"
#include "../kpm/kpm.h"

/*
 * LKM feature-control stub: the control-feature supercall is a
 * forward-looking API.  The LKM does not yet have runtime-togglable
 * features; add real handlers here as features land.
 */
#include <linux/string.h>
#include <linux/uaccess.h>

long kp_control_feature_sc(const char __user *uname, int state)
{
	char name[64];
	long len = strncpy_from_user(name, uname, sizeof(name));
	if (len <= 0)
		return -EINVAL;

	/* No LKM-side features are togglable yet. */
	(void)state;
	return -ENOENT;
}

long kp_handle_supercall(long cmd, long a1, long a2, long a3, long a4)
{
	/* Debug: log every supercall the manager/root app issues. */
	logki("supercall cmd 0x%lx a1=%lx a2=%lx a3=%lx a4=%lx\n", cmd, a1, a2, a3, a4);

	switch (cmd) {
	case SUPERCALL_HELLO:
		logki(SUPERCALL_HELLO_ECHO "\n");
		return SUPERCALL_HELLO_MAGIC;
	case SUPERCALL_KERNELPATCH_VER:
		return kpver;
	case SUPERCALL_KERNEL_VER:
		return kp_kver();
	case SUPERCALL_BUILD_TIME:
		return kp_su_unsupported_buildtime((char __user *)a1, (int)a2);

	case SUPERCALL_SU:
		return kp_su_sc((struct su_profile __user *)a1);
	case SUPERCALL_SU_TASK:
		return kp_su_task_sc((pid_t)a1, (struct su_profile __user *)a2);
	case SUPERCALL_SU_GRANT_UID:
		return kp_su_grant_uid_sc((struct su_profile __user *)a1);
	case SUPERCALL_SU_REVOKE_UID:
		return kp_su_revoke_uid_sc((uid_t)a1);
	case SUPERCALL_SU_NUMS:
		return kp_su_allow_uid_nums_sc();
	case SUPERCALL_SU_LIST:
		return kp_su_allow_uid_list_sc((uid_t __user *)a1, (int)a2);
	case SUPERCALL_SU_PROFILE:
		return kp_su_allow_uid_profile_sc((uid_t)a1, (struct su_profile __user *)a2);
	case SUPERCALL_SU_GET_PATH:
		return kp_su_get_path_sc((char __user *)a1, (int)a2);
	case SUPERCALL_SU_RESET_PATH:
		return kp_su_reset_path_sc((const char __user *)a1);

	case SUPERCALL_KPM_LOAD:
		return kp_kpm_load_sc((const char __user *)a1, (const char __user *)a2,
				      (void __user *)a3);
	case SUPERCALL_KPM_UNLOAD:
		return kp_kpm_unload_sc((const char __user *)a1, (void __user *)a2);
	case SUPERCALL_KPM_CONTROL:
		return kp_kpm_control_sc((const char __user *)a1, (const char __user *)a2,
					 (char __user *)a3, (int)a4);
	case SUPERCALL_KPM_NUMS:
		return kp_kpm_nums_sc();
	case SUPERCALL_KPM_LIST:
		return kp_kpm_list_sc((char __user *)a1, (int)a2);
	case SUPERCALL_KPM_INFO:
		return kp_kpm_info_sc((const char __user *)a1, (char __user *)a2, (int)a3);
		case SUPERCALL_CONTROL_FEATURE:
		return kp_control_feature_sc((const char __user *)a1, (int)a2);

	default:
		logkd("unsupported supercall cmd 0x%lx\n", cmd);
		return -ENOSYS;
	}
}
