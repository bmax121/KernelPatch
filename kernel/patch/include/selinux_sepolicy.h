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
 * KernelSU-style deep copy of the clean SELinux policy (see KernelSU's
 * ksu_dup_sepolicy / backup_sepolicy).  At post-fs-data "before" the live
 * policy is still the untouched boot policy; we deep-copy it -- serialize with
 * security_read_policy(), rebuild with policydb_read(), restore the serialized
 * length, load the initial SIDs into our own sidtab -- and answer
 * context/access queries against that copy instead of the (post-reload) live
 * one.
 *
 * The copy owns every inner table (policydb_read rebuilds them all), so no
 * fixup loops are needed and the queries go through the ss/ wrappers with
 * policydb + sidtab passed explicitly -- the same way on every supported
 * kernel, with no fake struct selinux_state.
 *
 * AOSP Android config bits: the policydb_write() hook in
 * patch/android/sepolicy_flags.c ORs android_netlink_route/getneigh into the
 * serialized policy -- the same fix KernelSU applies to the blob's config word
 * by hand.
 */

/* vmalloc/vfree with the *_noprof fallback (GKI 6.12 renamed them). */
void *kp_vmalloc(unsigned long size);
void kp_vfree(const void *addr);

/* Install anything needed once at boot. */
int selinux_sepolicy_init(void);

/* KernelSU-style deep copy of the current clean policy (post-fs-data before). */
int selinux_sepolicy_snapshot(void);

bool selinux_sepolicy_backup_ready(void);

/* Query helpers that answer against the deep copy. */
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
