// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Ported from kernel/patch/common/sucompat.c (allowlist part only; the execve
 * interception hooks are out of scope for the LKM framework).
 */
#include "sucompat.h"
#include "kstorage.h"

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"

#define KP_SU_GROUP 0 /* KSTORAGE_SU_LIST_GROUP */

static const char default_su_path[] = SU_PATH; /* "/system/bin/kp" */

static int su_group = -1;

bool kp_is_su_allow_uid(uid_t uid)
{
	if (su_group < 0)
		return false;
	rcu_read_lock();
	const struct kp_kstorage *ks = kp_kstorage_get(su_group, (long)uid);
	bool ok = !IS_ERR(ks);
	rcu_read_unlock();
	return ok;
}

int kp_su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext)
{
	if (su_group < 0)
		return -ENODEV;
	struct su_profile profile;
	memset(&profile, 0, sizeof(profile));
	profile.uid = uid;
	profile.to_uid = to_uid;
	if (scontext)
		strscpy(profile.scontext, scontext, sizeof(profile.scontext));
	int rc = kp_kstorage_write(su_group, (long)uid, &profile, 0, sizeof(profile), false);
	logki("allow uid %u -> %u (sctx %s) rc=%d\n", uid, to_uid, profile.scontext, rc);
	return rc;
}

int kp_su_remove_allow_uid(uid_t uid)
{
	if (su_group < 0)
		return -ENODEV;
	int rc = kp_kstorage_remove(su_group, (long)uid);
	logki("disallow uid %u rc=%d\n", uid, rc);
	return rc;
}

int kp_su_allow_uid_nums(void)
{
	if (su_group < 0)
		return 0;
	return kp_kstorage_group_size(su_group);
}

int kp_su_allow_uids(uid_t *out_uids, int out_num)
{
	if (su_group < 0)
		return -ENODEV;
	long ids[128];
	int n = kp_kstorage_list_ids(su_group, ids, ARRAY_SIZE(ids), false);
	if (n < 0)
		return n;
	if (n > out_num)
		n = out_num;
	for (int i = 0; i < n; i++)
		out_uids[i] = (uid_t)ids[i];
	return n;
}

int kp_su_allow_uid_profile(uid_t uid, struct su_profile *out_profile)
{
	if (su_group < 0)
		return -ENODEV;
	rcu_read_lock();
	const struct kp_kstorage *ks = kp_kstorage_get(su_group, (long)uid);
	if (IS_ERR(ks)) {
		rcu_read_unlock();
		return PTR_ERR(ks);
	}
	memcpy(out_profile, ks->data, sizeof(*out_profile));
	rcu_read_unlock();
	return 0;
}

#define KP_SU_PATH_MAX_LEN 128

static char current_su_path[KP_SU_PATH_MAX_LEN];

const char *kp_su_get_path(void)
{
	return current_su_path[0] ? current_su_path : default_su_path;
}

int kp_su_reset_path(const char *path)
{
	if (!path || !path[0])
		return -EINVAL;
	/* Copy into a static buffer: the caller (kp_su_reset_path_sc) frees its
	 * strndup_user buffer, so storing the pointer would dangle. */
	strscpy(current_su_path, path, sizeof(current_su_path));
	logki("su path reset to %s\n", current_su_path);
	return 0;
}

int kp_sucompat_init(void)
{
	su_group = kp_kstorage_alloc_group();
	if (su_group < 0) {
		logke("failed to alloc kstorage group for su allowlist\n");
		return -ENOMEM;
	}
	current_su_path[0] = '\0';
	/* Shell and root are allowed by default with the magisk domain, matching
	 * KP's all_allow_sctx = ALL_ALLOW_SCONTEXT_MAGISK. The u:r:kernel:s0
	 * domain cannot exec /system/bin/sh, so the root shell needs this. */
	kp_su_add_allow_uid(2000, 0, ALL_ALLOW_SCONTEXT_MAGISK);
	kp_su_add_allow_uid(0, 0, ALL_ALLOW_SCONTEXT_MAGISK);
	logki("su allowlist ready (group %d)\n", su_group);
	return 0;
}
