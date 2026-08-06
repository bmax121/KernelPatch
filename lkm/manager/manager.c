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
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/uaccess.h>

#include "../include/kp_lkm.h"
#include <hook.h>

#define KP_PACKAGES_LIST "/data/system/packages.list"
#define KP_PACKAGES_LIST_TMP "/data/system/packages.list.tmp"
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

/* Parse /data/system/packages.list for @package and return its uid. With
 * use_tmp the staged packages.list.tmp is read instead: the rename LSM hook
 * fires before the rename's d_move, so at that instant the tmp file holds the
 * post-update content while packages.list is still the pre-update one. */
static uid_t kp_lookup_package_uid(const char *package, int use_tmp)
{
	const char *path = use_tmp ? KP_PACKAGES_LIST_TMP : KP_PACKAGES_LIST;
	struct file *fp;
	loff_t fsize;
	char *buf, *cursor, *end;
	uid_t uid = KP_INVALID_APPID;

	fp = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
	if (IS_ERR(fp)) {
		logke("open %s failed: %ld\n", path, PTR_ERR(fp));
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

static void kp_crown_manager(int manager_idx, int use_tmp)
{
	const char *pkg = kp_trusted_managers[manager_idx].package;
	uid_t uid = kp_lookup_package_uid(pkg, use_tmp);

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
	int use_tmp;
	bool found;
};

static void kp_scan_apk_dir(const char *dir, int depth, bool *found, int use_tmp);

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
		kp_scan_apk_dir(path, sc->depth - 1, &sc->found, sc->use_tmp);
	} else if (d_type == DT_REG && namelen == 8 && !strncmp(name, "base.apk", 8)) {
		int idx = kp_manager_apk_match(path);
		if (idx >= 0) {
			kp_crown_manager(idx, sc->use_tmp);
			sc->found = true;
		}
	}
	return sc->found ? FILLDIR_STOP : FILLDIR_CONTINUE;
}

static void kp_scan_apk_dir(const char *dir, int depth, bool *found, int use_tmp)
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
	sc.use_tmp = use_tmp;
	sc.found = *found;
	iterate_dir(fp, &sc.ctx);
	*found = sc.found;
	filp_close(fp, NULL);
}

static int kp_manager_scan(int use_tmp)
{
	bool found = false;

	/* /data/app/<pkg>-N/base.apk (pre-11) and /data/app/~~h/<pkg>-h/base.apk
	 * (11+): depth 2 covers both. */
	kp_scan_apk_dir(KP_DATA_APP, 2, &found, use_tmp);
	if (!found)
		logki("trusted manager not found yet (scan incomplete or not installed)\n");
	return found ? 0 : -ENOENT;
}

static void kp_manager_scan_work_fn(struct work_struct *work)
{
	kp_manager_scan(0);
}

int kp_manager_refresh(void)
{
	return kp_manager_scan(0);
}

/* Re-derive from the staged packages.list.tmp; used by the rename hook which
 * fires before the tmp->main rename's d_move completes. */
int kp_manager_refresh_from_packages_list_tmp(void)
{
	return kp_manager_scan(1);
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

/* ---- packages.list rename -> re-derive manager uid ----------------------- */

#define KP_PACKAGES_LIST_TMP_SUFFIX "/system/packages.list.tmp"

/* Must match dentry_path_raw() exactly (note the const) — kCFI type-hashes the
 * indirect call, and a non-const first arg panics __cfi_slowpath_diag. */
typedef char *(*kp_dentry_path_raw_t)(const struct dentry *dentry, char *buf, int buflen);
static kp_dentry_path_raw_t kp_dentry_path_raw;
/* Track which LSM rename symbol was hooked so it can be removed on exit. */
static unsigned long kp_rename_hook_addr;
static void *kp_rename_hook_cb;

static bool kp_path_has_suffix(const char *path, const char *suffix)
{
	size_t plen, slen;

	if (!path || !suffix)
		return false;
	plen = strlen(path);
	slen = strlen(suffix);
	if (plen < slen)
		return false;
	return strcmp(path + plen - slen, suffix) == 0;
}

/* After packages.list.tmp is renamed into place, re-derive the manager uid.
 * The after-hook on the LSM rename runs before the rename's d_move, so the
 * staged packages.list.tmp still holds the post-update content. no_sanitize:
 * the dentry_path_raw call below is a raw resolved function pointer; even with
 * a matching type, don't let a kCFI check turn a benign mismatch into a panic. */
__attribute__((no_sanitize("cfi")))
static void kp_refresh_manager_on_list_rename(struct dentry *dentry)
{
	char path[128];
	char *buf;

	if (!dentry || !kp_dentry_path_raw)
		return;
	buf = kp_dentry_path_raw(dentry, path, sizeof(path));
	if (IS_ERR(buf))
		return;
	if (kp_path_has_suffix(buf, KP_PACKAGES_LIST_TMP_SUFFIX)) {
		logki("packages.list rename matched: %s\n", buf);
		kp_manager_refresh_from_packages_list_tmp();
	}
}

static void kp_after_security_path_rename(hook_fargs5_t *args, void *udata)
{
	(void)udata;
	if ((long)args->ret >= 0)
		kp_refresh_manager_on_list_rename((struct dentry *)args->arg1);
}

static void kp_after_security_inode_rename(hook_fargs5_t *args, void *udata)
{
	(void)udata;
	if ((long)args->ret >= 0)
		kp_refresh_manager_on_list_rename((struct dentry *)args->arg1);
}

void hook_rename_lsm(void)
{
	unsigned long addr;
	hook_err_t rc;

	kp_dentry_path_raw = (kp_dentry_path_raw_t)kallsyms_lookup_name("dentry_path_raw");
	if (!kp_dentry_path_raw) {
		logkw("no symbol: dentry_path_raw\n");
		return;
	}

	addr = kallsyms_lookup_name("security_path_rename");
	if (addr) {
		kp_rename_hook_addr = addr;
		kp_rename_hook_cb = kp_after_security_path_rename;
		rc = hook_wrap5((void *)addr, 0, kp_after_security_path_rename, 0);
		logki("hook security_path_rename rc: %d\n", rc);
		return;
	}

	addr = kallsyms_lookup_name("security_inode_rename");
	if (addr) {
		kp_rename_hook_addr = addr;
		kp_rename_hook_cb = kp_after_security_inode_rename;
		rc = hook_wrap5((void *)addr, 0, kp_after_security_inode_rename, 0);
		logki("hook security_inode_rename rc: %d\n", rc);
		return;
	}

	logkw("no symbol: security_path_rename/security_inode_rename\n");
}

void hook_rename_lsm_exit(void)
{
	if (kp_rename_hook_addr) {
		/* Installed as hook_wrap5(addr, 0, cb, 0); pass the same (before,
		 * after) pair to unwrap so the chain item matches. */
		hook_unwrap((void *)kp_rename_hook_addr, 0, kp_rename_hook_cb);
		kp_rename_hook_addr = 0;
		kp_rename_hook_cb = NULL;
		logki("rename LSM hook removed\n");
	}
}
