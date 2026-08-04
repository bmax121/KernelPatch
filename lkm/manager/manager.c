// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Manager scan, mirroring KernelSU's throne_tracker flow but using the APatch
 * trusted-cert table. packages.list is plain text on all Android versions, so
 * it is the uid source; the APK cert check anchors trust.
 */
#include "manager.h"
#include "apk_sign.h"

#include <linux/dirent.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/uaccess.h>

#include "../include/kp_lkm.h"

#define KP_PACKAGES_LIST "/data/system/packages.list"
#define KP_DATA_APP "/data/app"
#define KP_PATH_LEN 256

/* filldir calling convention changed in 6.1 (int -> bool). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN bool
#define FILLDIR_CONTINUE true
#define FILLDIR_STOP false
#else
#define FILLDIR_RETURN int
#define FILLDIR_CONTINUE 0
#define FILLDIR_STOP -EINVAL
#endif

static uid_t kp_manager_appid_value = KP_INVALID_APPID;
static struct work_struct kp_manager_scan_work;

uid_t kp_manager_appid(void)
{
	return READ_ONCE(kp_manager_appid_value);
}

bool kp_is_manager_uid(uid_t uid)
{
	uid_t appid = kp_manager_appid();
	if (appid == KP_INVALID_APPID)
		return false;
	/* uid may include a user-id offset; compare the appid part. */
	return (uid % 100000) == appid;
}

/* Parse /data/system/packages.list for @package and return its uid. */
static uid_t kp_lookup_package_uid(const char *package)
{
	struct file *fp;
	loff_t fsize;
	char *buf, *cursor, *end;
	uid_t uid = KP_INVALID_APPID;

	fp = filp_open(KP_PACKAGES_LIST, O_RDONLY | O_NOFOLLOW, 0);
	if (IS_ERR(fp)) {
		logke("open %s failed: %ld\n", KP_PACKAGES_LIST, PTR_ERR(fp));
		return KP_INVALID_APPID;
	}
	fsize = i_size_read(file_inode(fp));
	if (fsize <= 0 || fsize > (1 << 20))
		goto out_close;

	buf = kvzalloc(fsize + 1, GFP_KERNEL);
	if (!buf)
		goto out_close;
	{
		loff_t pos = 0;
		if (kernel_read(fp, buf, fsize, &pos) != fsize) {
			kvfree(buf);
			goto out_close;
		}
	}

	cursor = buf;
	end = buf + fsize;
	while (cursor < end) {
		char *line = cursor, *line_end = cursor, *pkg, *uid_str;
		unsigned long long u = 0;

		while (line_end < end && *line_end != '\n' && *line_end != '\r')
			line_end++;
		if (line_end < end) {
			*line_end = '\0';
			cursor = line_end + 1;
		} else {
			cursor = end;
		}

		while (*line == ' ' || *line == '\t')
			line++;
		if (!*line)
			continue;
		pkg = line;
		while (*line && *line != ' ' && *line != '\t')
			line++;
		if (!*line)
			continue;
		*line++ = '\0';
		while (*line == ' ' || *line == '\t')
			line++;
		uid_str = line;
		while (*line && *line != ' ' && *line != '\t')
			line++;
		*line = '\0';

		if (strcmp(pkg, package) != 0)
			continue;
		if (kstrtoull(uid_str, 10, &u) || u > UINT_MAX)
			break;
		uid = (uid_t)u;
		break;
	}
	kvfree(buf);

out_close:
	filp_close(fp, NULL);
	return uid;
}

static void kp_crown_manager(int manager_idx)
{
	const char *pkg = kp_trusted_managers[manager_idx].package;
	uid_t uid = kp_lookup_package_uid(pkg);

	if (uid == KP_INVALID_APPID) {
		logke("found manager apk for %s but no uid in packages.list\n", pkg);
		return;
	}
	WRITE_ONCE(kp_manager_appid_value, uid);
	logki("trusted manager crowned: %s uid=%u\n", pkg, uid);
}

struct kp_scan_ctx {
	struct dir_context ctx;
	char parent[KP_PATH_LEN];
	int depth;
	bool found;
};

static void kp_scan_apk_dir(const char *dir, int depth, bool *found);

static FILLDIR_RETURN kp_dir_actor(struct dir_context *ctx, const char *name, int namelen, loff_t off, u64 ino,
				   unsigned int d_type)
{
	struct kp_scan_ctx *sc = container_of(ctx, struct kp_scan_ctx, ctx);
	char path[KP_PATH_LEN];
	(void)off; (void)ino;

	if (sc->found)
		return FILLDIR_STOP;
	if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
		return FILLDIR_CONTINUE;
	if (snprintf(path, sizeof(path), "%s/%.*s", sc->parent, namelen, name) >= (int)sizeof(path))
		return FILLDIR_CONTINUE;

	if (d_type == DT_DIR && sc->depth > 0) {
		kp_scan_apk_dir(path, sc->depth - 1, &sc->found);
	} else if (d_type == DT_REG && namelen == 8 && !strncmp(name, "base.apk", 8)) {
		int idx = kp_manager_apk_match(path);
		if (idx >= 0) {
			kp_crown_manager(idx);
			sc->found = true;
		}
	}
	return sc->found ? FILLDIR_STOP : FILLDIR_CONTINUE;
}

static void kp_scan_apk_dir(const char *dir, int depth, bool *found)
{
	struct file *fp;
	struct kp_scan_ctx sc;

	if (*found)
		return;
	fp = filp_open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
	if (IS_ERR(fp))
		return;
	memset(&sc, 0, sizeof(sc));
	sc.ctx.actor = kp_dir_actor;
	strscpy(sc.parent, dir, sizeof(sc.parent));
	sc.depth = depth;
	sc.found = *found;
	iterate_dir(fp, &sc.ctx);
	*found = sc.found;
	filp_close(fp, NULL);
}

static void kp_manager_scan_work_fn(struct work_struct *work)
{
	bool found = false;

	/* /data/app/<pkg>-N/base.apk (pre-11) and /data/app/~~h/<pkg>-h/base.apk
	 * (11+): depth 2 covers both. */
	kp_scan_apk_dir(KP_DATA_APP, 2, &found);
	if (!found)
		logki("trusted manager not found yet (scan incomplete or not installed)\n");
}

void kp_manager_refresh(void)
{
	kp_manager_scan_work_fn(&kp_manager_scan_work);
}

int kp_manager_init(void)
{
	/* Run the scan synchronously in the module_init context instead of a
	 * workqueue. The workqueue runs as a kernel thread in the u:r:kernel:s0
	 * SELinux domain, which many devices (e.g. MTK) deny from reading
	 * /data/app and /data/system/packages.list (dac_read_search/dac_override
	 * denied). The insmod/kpinit caller, by contrast, is root (su domain) and
	 * usually has permission to read /data. */
	INIT_WORK(&kp_manager_scan_work, kp_manager_scan_work_fn);
	kp_manager_scan_work_fn(&kp_manager_scan_work);
	return 0;
}
