/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Supercall-level SU handlers (sc_ = supercall, distinct from the sucompat
 * allowlist layer they delegate to).
 */
#ifndef _KP_LKM_SU_H_
#define _KP_LKM_SU_H_
#include <linux/types.h>

struct su_profile;

long kp_su_sc(const struct su_profile __user *uprofile);
long kp_su_task_sc(pid_t pid, const struct su_profile __user *uprofile);
long kp_su_grant_uid_sc(const struct su_profile __user *uprofile);
long kp_su_revoke_uid_sc(uid_t uid);
long kp_su_allow_uid_nums_sc(void);
long kp_su_allow_uid_list_sc(uid_t __user *uids, int max);
long kp_su_allow_uid_profile_sc(uid_t uid, struct su_profile __user *out);
long kp_su_get_path_sc(char __user *ubuf, int buf_len);
long kp_su_reset_path_sc(const char __user *upath);
long kp_su_unsupported_buildtime(char __user *ubuf, int buf_len);

#endif /* _KP_LKM_SU_H_ */
