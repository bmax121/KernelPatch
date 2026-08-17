/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef _KP_SELINUX_SEPOLICY_H_
#define _KP_SELINUX_SEPOLICY_H_

#include <ktypes.h>

struct selinux_state;
struct av_decision;

/*
 * KernelSU-style backup of the clean SELinux policy (see KernelSU's
 * ksu_dup_sepolicy / backup_sepolicy).  At post-fs-data "before" the live
 * policy is still the untouched boot policy; we deep-copy it into a standalone
 * policydb + sidtab and answer context/access queries against that clean
 * snapshot instead of the (post-reload) live one.
 *
 * Two paths:
 *  - kernels 4.19 .. 6.3 (compat range): the security_* helpers still take a
 *    struct selinux_state *, so we point a fake state at the backup
 *    (policydb_read + policydb_load_isids construction).
 *  - kernels >= 6.4: the helpers no longer take a state, so we build the
 *    backup with the staged security_load_policy() and re-implement the thin
 *    *_with_policy wrappers on top of the resolvable ss/ internals
 *    (string_to_context_struct / sidtab_* / context_struct_compute_av).
 */

/* vmalloc/vfree with the *_noprof fallback (GKI 6.12 renamed them). */
void *kp_vmalloc(unsigned long size);
void kp_vfree(const void *addr);

/* Install anything needed once at boot. */
int selinux_sepolicy_init(void);

/* Deep-copy the current clean policy (call at post-fs-data before). */
int selinux_sepolicy_snapshot(void);

bool selinux_sepolicy_backup_ready(void);

/* Query helpers that answer against the backup policy. */
int selinux_sepolicy_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
int selinux_sepolicy_sid_to_context(u32 sid, char **scontext, u32 *scontext_len);
int selinux_sepolicy_context_str_to_sid(const char *scontext, u32 *out_sid, gfp_t gfp);
void selinux_sepolicy_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

/* Sequence value the fake /sys/fs/selinux/status page uses (>= 6.7), and the
 * access-query response's seqno.  A clean device exposes sequence=4/policyload=1
 * in the status page but latest_granting=1 in the access response -- the two are
 * different counters, so they must NOT be equal (detectors compare both). */
u32 selinux_sepolicy_clean_seq(void);
#define KP_AVD_CLEAN_SEQNO 1

/* Clean-eval scope (selinux_magisk_access_filter KPM mechanism): while entered,
 * the kernel's context_struct_compute_av()/string_to_context_struct() get their
 * policydb argument redirected to the clean snapshot, so the caller's own
 * context/access query computes against the pre-root policy. */
int selinux_sepolicy_clean_eval_enter(void);
void selinux_sepolicy_clean_eval_leave(void);

#endif
