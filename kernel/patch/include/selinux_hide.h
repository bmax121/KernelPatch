/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef _KP_SELINUX_HIDE_H_
#define _KP_SELINUX_HIDE_H_

#include <common.h>
#define KP_SELINUX_HIDE_MIN_VERSION VERSION(4, 19, 0)
#define KP_SELINUX_NEW_VERSION VERSION(5, 0, 0)
#define KP_SELINUX_WITHOUT_SEPOLICY_STATE_VERSION VERSION(6, 6, 0)
/* Resolve symbols / cache support state at boot. Never installs hooks. */

static bool selinux_hide_is_supported(void)
{
    return kver >= KP_SELINUX_HIDE_MIN_VERSION;
}
static bool selinux_hide_is_new_version(void)
{
    return kver >= KP_SELINUX_NEW_VERSION;
}
static bool selinux_hide_is_without_sepolicy_state_version(void)
{
    return kver >= KP_SELINUX_WITHOUT_SEPOLICY_STATE_VERSION;
}

int selinux_hide_init(void);

/* Called from report_user_event for the post-fs-data before/after events.
 * args: "before" -> install hooks (also honors the /data/adb/ap file), "after" -> finalize. */
int selinux_hide_post_fs_data(const char *args);

long selinux_hide_control(int state);

/* Current query-log level (see the KP_QLOG_* block in selinux_hide.c); read by
 * selinux_sepolicy.c for its level-2 redirect logging. */
int selinux_hide_query_log_level(void);

/* Whether the feature is currently active. */
int selinux_hide_is_enabled(void);

/* Resolve a (possibly LTO-mangled) static symbol: try the exact name, then a
 * kallsyms_on_each_symbol walk covering <name>.<n> / <name>.llvm.<hash> /
 * <name>$... suffixes. */
unsigned long lookup_name_with_suffix(const char *base);
unsigned long kallsyms_lookup_name_by_suffix(const char *name);
#endif
