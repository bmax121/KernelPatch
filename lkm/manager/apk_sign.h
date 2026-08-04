/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * APatch manager APK signature verification, ported from
 * kernel/patch/android/userd.c. Verifies that a base.apk is signed by one of
 * the trusted APatch certificates by hashing the v2 signing-block certificate
 * with SHA256 and comparing against the trusted digests.
 */
#ifndef _KP_LKM_APK_SIGN_H_
#define _KP_LKM_APK_SIGN_H_
#include <linux/types.h>

struct kp_trusted_manager {
	const char *package;
	const u8 digest[32];
};

/* Trusted (package, cert sha256) table. NULL-package terminated. */
extern const struct kp_trusted_manager kp_trusted_managers[];

/* Number of entries in kp_trusted_managers. */
int kp_trusted_manager_count(void);

/* Verify the APK at @path against every trusted cert digest.
 * Returns the index into kp_trusted_managers on match, or -1. */
int kp_manager_apk_match(const char *path);

#endif /* _KP_LKM_APK_SIGN_H_ */
