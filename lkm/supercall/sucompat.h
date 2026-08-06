/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * SU allowlist management, ported from kernel/patch/common/sucompat.c.
 * The allowlist lives in kstorage group 0 (KSTORAGE_SU_LIST_GROUP), keyed by
 * uid, holding a struct su_profile blob.
 */
#ifndef _KP_LKM_SUCOMPAT_H_
#define _KP_LKM_SUCOMPAT_H_
#include <linux/types.h>

struct su_profile;

/* Initialize the allowlist: allocate kstorage group 0, pre-allow shell (2000)
 * and root (0). */
int kp_sucompat_init(void);

bool kp_is_su_allow_uid(uid_t uid);

int kp_su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext);

int kp_su_remove_allow_uid(uid_t uid);

int kp_su_allow_uid_nums(void);

/* Fill out_uids with allowed uids; returns count. */
int kp_su_allow_uids(uid_t *out_uids, int out_num);

int kp_su_allow_uid_profile(uid_t uid, struct su_profile *out_profile);

/* APatch module exclude flag (kstorage group KSTORAGE_EXCLUDE_LIST_GROUP). */
int kp_su_set_ap_mod_exclude(uid_t uid, int exclude);
int kp_su_get_ap_mod_exclude(uid_t uid);

/* Get/set the su binary path (default "/system/bin/kp"). */
const char *kp_su_get_path(void);
int kp_su_reset_path(const char *path);

/* Auto-load APatch config (/data/adb/ap/su_path + package_config) at module
 * init. Returns number of allow entries loaded, or negative error. */
int kp_su_load_config(void);

#endif /* _KP_LKM_SUCOMPAT_H_ */
