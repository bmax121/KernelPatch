/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef _KP_SELINUX_HIDE_H_
#define _KP_SELINUX_HIDE_H_

#include <common.h>

/* ---- kernel-version gates ----
 *
 * Every kver threshold the feature uses lives here; the .c files ask the
 * predicates below instead of comparing kver themselves.  Adding a gate means
 * adding one name here and one predicate, not another VERSION() literal in a
 * hot file.
 */
#define KP_SELINUX_HIDE_MIN_VERSION               VERSION(4, 19, 0) /* feature floor */
#define KP_SELINUX_NEW_VERSION                    VERSION(5, 5, 0) /* snapshot handlers */
#define KP_SELINUX_WITHOUT_SEPOLICY_STATE_VERSION VERSION(6, 6, 0) /* no selinux_state */
#define KP_SELINUX_VMA_LAYOUT_VERSION             VERSION(6, 1, 0) /* vm_page_prot/flags offsets */
#define KP_SELINUX_FOPS_SHIFT_512_VERSION         VERSION(5, 12, 0) /* fops entry shift */
#define KP_SELINUX_FOPS_SHIFT_51_VERSION          VERSION(5, 1, 0)
#define KP_SELINUX_LIVE_FAST_VERSION              VERSION(6, 6, 0) /* direct live sidtab insert */
#define KP_SELINUX_STATUS_COUNTERS_VERSION        VERSION(6, 7, 0) /* status sequence/policyload */

/* Resolve symbols / cache support state at boot. Never installs hooks. */

static inline bool selinux_hide_is_supported(void)
{
    return kver >= KP_SELINUX_HIDE_MIN_VERSION;
}
static inline bool selinux_hide_is_new_version(void)
{
    return kver >= KP_SELINUX_NEW_VERSION;
}
static inline bool selinux_hide_is_without_sepolicy_state_version(void)
{
    return kver >= KP_SELINUX_WITHOUT_SEPOLICY_STATE_VERSION;
}
static inline bool selinux_hide_has_vma_layout(void)
{
    return kver >= KP_SELINUX_VMA_LAYOUT_VERSION;
}
static inline bool selinux_hide_has_live_fast_path(void)
{
    return kver >= KP_SELINUX_LIVE_FAST_VERSION;
}
static inline bool selinux_hide_has_status_counters(void)
{
    return kver >= KP_SELINUX_STATUS_COUNTERS_VERSION;
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
