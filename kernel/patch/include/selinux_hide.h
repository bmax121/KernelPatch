/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef _KP_SELINUX_HIDE_H_
#define _KP_SELINUX_HIDE_H_

/* 
 *
 * Enabled only on kernels >= 4.19 (below that even a forced enable is a no-op).
 * Control path mirrors kp_control_feature_sc: the manager can toggle it via the
 * SUPERCALL_CONTROL_FEATURE supercall with name "selinux_hide", or create the
 * file /data/adb/ap/selinux_hide so it is auto-enabled at post-fs-data.
 *
 * At post-fs-data "before" the live policy is still the untouched boot policy;
 * we deep-copy it (see selinux_sepolicy.c) so the context/access/setprocattr
 * hooks answer against that clean snapshot even after APatch/Magisk reloads the
 * policy, and apps (uid >= 10000) see a fake /sys/fs/selinux/status that always
 * reports enforcing with a clean sequence/policyload.  On kernels outside the
 * 4.19..6.3 backup range the write hooks fall back to the live policy and only
 * the status hide remains.
 */

/* Resolve symbols / cache support state at boot. Never installs hooks. */
int selinux_hide_init(void);

/* Called from report_user_event for the post-fs-data before/after events.
 * args: "before" -> install hooks (also honors the /data/adb/ap file), "after" -> finalize. */
int selinux_hide_post_fs_data(const char *args);

/* Supercall control entry. state: 1 = enable, 0 = disable, < 0 = query.
 * Returns: query -> 1/0 (on/off), or -EOPNOTSUPP when the kernel is too old;
 * set -> 0 on success or a negative errno. */
long selinux_hide_control(int state);

/* Whether the feature is currently active. */
int selinux_hide_is_enabled(void);

/* Resolve a (possibly LTO-mangled) static symbol: try the exact name, then a
 * kallsyms_on_each_symbol walk covering <name>.<n> / <name>.llvm.<hash> /
 * <name>$... suffixes. */
unsigned long lookup_name_with_suffix(const char *base);
unsigned long kallsyms_lookup_name_by_suffix(const char *name);
#endif
