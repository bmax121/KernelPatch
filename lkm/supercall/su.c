// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * SU supercall handlers, backed by sucompat (allowlist) + accctl (creds).
 */
#include "su.h"
#include "accctl.h"
#include "sucompat.h"

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"

long kp_su_unsupported_buildtime(char __user *ubuf, int buf_len)
{
	int len = sizeof(KP_LKM_VERSION_STRING);
	if (buf_len <= len)
		return -ENOBUFS;
	if (copy_to_user(ubuf, KP_LKM_VERSION_STRING, len))
		return -EFAULT;
	return 0;
}

long kp_su_sc(const struct su_profile __user *uprofile)
{
	struct su_profile *profile;
	long rc;

	if (!uprofile)
		return -EINVAL;
	profile = memdup_user(uprofile, sizeof(*profile));
	if (IS_ERR(profile))
		return PTR_ERR(profile);

	logki("SU requested for to_uid=%u scontext=%.*s\n", profile->to_uid,
	      (int)sizeof(profile->scontext), profile->scontext);

	rc = kp_commit_su(profile->to_uid, profile->scontext);
	kfree(profile);
	return rc;
}

long kp_su_task_sc(pid_t pid, const struct su_profile __user *uprofile)
{
	struct su_profile *profile;
	long rc;

	if (!uprofile)
		return -EINVAL;
	profile = memdup_user(uprofile, sizeof(*profile));
	if (IS_ERR(profile))
		return PTR_ERR(profile);

	rc = kp_task_su(pid, profile->to_uid, profile->scontext);
	kfree(profile);
	return rc;
}

long kp_su_grant_uid_sc(const struct su_profile __user *uprofile)
{
	struct su_profile *profile;
	long rc;

	if (!uprofile)
		return -EINVAL;
	profile = memdup_user(uprofile, sizeof(*profile));
	if (IS_ERR(profile))
		return PTR_ERR(profile);

	rc = kp_su_add_allow_uid(profile->uid, profile->to_uid, profile->scontext);
	kfree(profile);
	return rc;
}

long kp_su_revoke_uid_sc(uid_t uid)
{
	return kp_su_remove_allow_uid(uid);
}

long kp_su_allow_uid_nums_sc(void)
{
	long n = kp_su_allow_uid_nums();
	logki("su_allow_uid_nums -> %ld\n", n);
	return n;
}

long kp_su_allow_uid_list_sc(uid_t __user *uids, int max)
{
	uid_t list[128];
	int n = kp_su_allow_uids(list, ARRAY_SIZE(list));
	if (n < 0)
		return n;
	if (n > max)
		n = max;
	if (copy_to_user(uids, list, n * sizeof(uid_t)))
		return -EFAULT;
	logki("su_allow_uid_list -> %d uids: [%u %u %u %u]\n", n, list[0], list[1], list[2], list[3]);
	return n;
}

long kp_su_allow_uid_profile_sc(uid_t uid, struct su_profile __user *out)
{
	struct su_profile profile;
	int rc = kp_su_allow_uid_profile(uid, &profile);
	if (rc)
		return rc;
	if (copy_to_user(out, &profile, sizeof(profile)))
		return -EFAULT;
	return 0;
}

long kp_su_get_path_sc(char __user *ubuf, int buf_len)
{
	const char *path = kp_su_get_path();
	int len = strlen(path);
	logki("su_get_path: path=%s len=%d buf_len=%d\n", path, len, buf_len);
	if (buf_len <= len)
		return -ENOBUFS;
	if (copy_to_user(ubuf, path, len + 1))
		return -EFAULT;
	return 0;
}

long kp_su_reset_path_sc(const char __user *upath)
{
	char *path = strndup_user(upath, PATH_MAX);
	if (IS_ERR(path))
		return PTR_ERR(path);
	int rc = kp_su_reset_path(path);
	kfree(path);
	return rc;
}
