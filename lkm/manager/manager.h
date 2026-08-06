/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Trusted manager detection. Scans /data/app for a base.apk whose v2 signing
 * certificate matches a trusted APatch digest, looks up the package's uid from
 * /data/system/packages.list, and records it as the manager appid. Supercalls
 * are authenticated by comparing the caller's uid against that appid.
 */
#ifndef _KP_LKM_MANAGER_H_
#define _KP_LKM_MANAGER_H_
#include <linux/types.h>

#define KP_INVALID_APPID ((uid_t)-1)

/* Kick off the manager scan. Runs synchronously in the caller's context (the
 * root process that loaded the ko) so SELinux allows reading /data/app and
 * /data/system/packages.list — a workqueue would run in the denied kernel
 * domain. Call once from module init. */
int kp_manager_init(void);

/* Re-scan synchronously (e.g. retry if the first scan ran before the manager
 * was installed). Returns 0 if the manager was crowned. */
int kp_manager_refresh(void);

/* Re-scan reading the staged packages.list.tmp; called by the rename hook
 * (fires before the tmp->main rename's d_move, when .tmp holds the new data). */
int kp_manager_refresh_from_packages_list_tmp(void);

/* Hook security_path_rename (fallback security_inode_rename) so a
 * packages.list.tmp rename re-derives the trusted manager uid. */
void hook_rename_lsm(void);
void hook_rename_lsm_exit(void);

/* The detected manager appid (KP_INVALID_APPID if not found yet). */
uid_t kp_manager_appid(void);

/* True if @uid belongs to the trusted manager. */
bool kp_is_manager_uid(uid_t uid);

#endif /* _KP_LKM_MANAGER_H_ */
