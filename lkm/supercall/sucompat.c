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
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"

#define KP_SU_GROUP 0 /* KSTORAGE_SU_LIST_GROUP */
#define KP_EXCLUDE_GROUP 1 /* KSTORAGE_EXCLUDE_LIST_GROUP */

/* APatch config files, auto-read at module init. */
#define AP_SU_PATH_FILE "/data/adb/ap/su_path"
#define AP_PACKAGE_CONFIG_PATH "/data/adb/ap/package_config"

static const char default_su_path[] = SU_PATH; /* "/system/bin/kp" */

static int su_group = -1;
static int exclude_group = -1;

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

/* APatch module exclude flag (group KSTORAGE_EXCLUDE_LIST_GROUP), mirroring
 * kernel/patch/common/sucompat.c. The auto-loaded package_config writes here,
 * and the KPM-facing get/set_ap_mod_exclude delegates to these. */
int kp_su_set_ap_mod_exclude(uid_t uid, int exclude)
{
	if (exclude_group < 0)
		return -ENODEV;
	if (exclude)
		return kp_kstorage_write(exclude_group, (long)uid, &exclude, 0, sizeof(exclude), false);
	return kp_kstorage_remove(exclude_group, (long)uid);
}

int kp_su_get_ap_mod_exclude(uid_t uid)
{
	int exclude = 0;
	if (exclude_group < 0)
		return 0;
	int rc = kp_kstorage_read(exclude_group, (long)uid, &exclude, 0, sizeof(exclude), false);
	if (rc < 0)
		return 0;
	return exclude;
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
	exclude_group = kp_kstorage_alloc_group();
	if (exclude_group < 0)
		logkw("failed to alloc kstorage group for ap module exclude\n");
	current_su_path[0] = '\0';
	/* Shell and root are allowed by default with the magisk domain, matching
	 * KP's all_allow_sctx = ALL_ALLOW_SCONTEXT_MAGISK. The u:r:kernel:s0
	 * domain cannot exec /system/bin/sh, so the root shell needs this. */
	kp_su_add_allow_uid(2000, 0, ALL_ALLOW_SCONTEXT_MAGISK);
	kp_su_add_allow_uid(0, 0, ALL_ALLOW_SCONTEXT_MAGISK);
	logki("su allowlist ready (group %d)\n", su_group);
	return 0;
}

/* ---- APatch config auto-load at module init ----------------------------- */

/* Read a whole file into a vmalloc'd, NUL-terminated buffer (caller vfree()s).
 * Returns NULL on failure so the caller can fall back to the supercall path. */
static char *kp_read_config_file(const char *path, loff_t *out_len)
{
	struct file *filp;
	loff_t len, pos = 0;
	char *data;

	filp = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
	if (IS_ERR(filp)) {
		logkw("open %s failed: %ld\n", path, PTR_ERR(filp));
		return NULL;
	}
	len = vfs_llseek(filp, 0, SEEK_END);
	vfs_llseek(filp, 0, SEEK_SET);
	if (len <= 0) {
		filp_close(filp, NULL);
		logkw("%s empty\n", path);
		return NULL;
	}
	data = vmalloc(len + 1);
	if (!data) {
		filp_close(filp, NULL);
		logkw("%s alloc failed (%lld bytes)\n", path, len);
		return NULL;
	}
	if (kernel_read(filp, data, len, &pos) != len) {
		vfree(data);
		filp_close(filp, NULL);
		logkw("read %s failed\n", path);
		return NULL;
	}
	data[len] = '\0';
	filp_close(filp, NULL);
	if (out_len)
		*out_len = len;
	return data;
}

/* Port of userd.c parse_csv_field: returns a NUL-terminated field and advances
 * *line_ptr past the delimiter. */
static char *kp_parse_csv_field(char **line_ptr)
{
	char *start = *line_ptr;
	char *end;

	if (!start || *start == '\0')
		return NULL;

	while (*start == ' ' || *start == '\t')
		start++;
	end = start;
	while (*end && *end != ',' && *end != '\n' && *end != '\r')
		end++;

	{
		char delim = *end;

		if (end > start) {
			char *trim_end = end - 1;
			while (trim_end > start && (*trim_end == ' ' || *trim_end == '\t'))
				trim_end--;
			*(trim_end + 1) = '\0';
		} else {
			*start = '\0';
		}
		if (delim == ',')
			*line_ptr = end + 1;
		else
			*line_ptr = end;
	}
	return start;
}

/* Apply the package allowlist CSV "pkg,exclude,allow,uid,to_uid,sctx",
 * mirroring kpimg's load_ap_package_config() against the LKM allowlist.
 * Returns number of allow entries loaded, or negative error. */
static int kp_load_package_config(void)
{
	loff_t len = 0;
	char *content = kp_read_config_file(AP_PACKAGE_CONFIG_PATH, &len);
	char *line_start;
	int line_num = 0;
	int loaded_count = 0;
	int skipped_count = 0;

	if (!content)
		return -ENOENT;
	if (len > 10 * 1024 * 1024) {
		logkw("package_config too large: %lld\n", len);
		vfree(content);
		return -EFBIG;
	}

	logki("loading package_config, size: %lld\n", len);
	line_start = content;
	while (line_start < content + len) {
		char *line_end = line_start;
		int has_newline = 0;

		while (line_end < content + len && *line_end != '\n' && *line_end != '\r')
			line_end++;
		if (line_end < content + len) {
			has_newline = 1;
			*line_end = '\0';
		}

		line_num++;

		/* Skip CSV header */
		if (line_num == 1) {
			if (has_newline)
				line_start = line_end + 1;
			else
				break;
			continue;
		}

		{
			char *line_ptr = line_start;
			char *exclude_str, *allow_str, *uid_str, *to_uid_str, *sctx;
			unsigned long long uid_tmp = 0, to_uid_tmp = 0;
			unsigned long long exclude_tmp = 0, allow_tmp = 0;
			uid_t uid, to_uid;
			int exclude, allow;
			int valid_line = 1;

			kp_parse_csv_field(&line_ptr); /* skip pkg */
			exclude_str = kp_parse_csv_field(&line_ptr);
			allow_str = kp_parse_csv_field(&line_ptr);
			uid_str = kp_parse_csv_field(&line_ptr);
			to_uid_str = kp_parse_csv_field(&line_ptr);
			sctx = kp_parse_csv_field(&line_ptr);

			if (!uid_str || !to_uid_str || !sctx) {
				logkw("package_config: line %d missing required fields (uid/to_uid/sctx)\n",
				      line_num);
				valid_line = 0;
			} else {
				if (kstrtoull(uid_str, 10, &uid_tmp) || uid_tmp > UINT_MAX) {
					logkw("package_config: line %d invalid uid '%s'\n", line_num, uid_str);
					valid_line = 0;
				}
				if (valid_line && (kstrtoull(to_uid_str, 10, &to_uid_tmp) || to_uid_tmp > UINT_MAX)) {
					logkw("package_config: line %d invalid to_uid '%s'\n", line_num, to_uid_str);
					valid_line = 0;
				}
			}

			if (exclude_str && *exclude_str && kstrtoull(exclude_str, 10, &exclude_tmp) == 0)
				if (exclude_tmp > INT_MAX)
					exclude_tmp = INT_MAX;
			if (allow_str && *allow_str && kstrtoull(allow_str, 10, &allow_tmp) == 0)
				if (allow_tmp > INT_MAX)
					allow_tmp = INT_MAX;

			uid = (uid_t)uid_tmp;
			to_uid = (uid_t)to_uid_tmp;
			exclude = (int)exclude_tmp;
			allow = (int)allow_tmp;

			if (valid_line && allow) {
				int rc = kp_su_add_allow_uid(uid, to_uid, sctx);
				if (rc == 0)
					loaded_count++;
				else {
					logkw("package_config: line %d failed to add allow rule: %d\n",
					      line_num, rc);
					valid_line = 0;
				}
			}
			if (exclude)
				kp_su_set_ap_mod_exclude(uid, exclude);

			if (!valid_line)
				skipped_count++;
		}

		if (has_newline)
			line_start = line_end + 1;
		else
			break;
	}

	vfree(content);
	logki("package_config loaded: %d entries, skipped: %d\n", loaded_count, skipped_count);
	return loaded_count;
}

/* Auto-load the APatch config at module init (only meaningful on jailbroken
 * devices where /data/adb/ap exists at insmod time):
 *   - /data/adb/ap/su_path        -> su binary path
 *   - /data/adb/ap/package_config -> per-package allow/exclude rules
 * Failure is non-fatal: the manager can still configure via supercalls. */
int kp_su_load_config(void)
{
	loff_t len = 0;
	char *path = kp_read_config_file(AP_SU_PATH_FILE, &len);

	if (path) {
		size_t n = strlen(path);
		while (n > 0 && (path[n - 1] == '\n' || path[n - 1] == '\r'))
			path[--n] = '\0';
		if (path[0])
			kp_su_reset_path(path);
		vfree(path);
	}

	return kp_load_package_config();
}
