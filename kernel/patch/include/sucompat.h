/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_SUCOMPAT_H_
#define _KP_SUCOMPAT_H_

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <hook.h>

extern const char sh_path[];
extern const char default_su_path[];
extern const char legacy_su_path[];
extern const char apd_path[];

struct allow_uid
{
    uid_t uid;
    struct su_profile profile;
    struct list_head list;
    struct rcu_head rcu;
};

int is_su_allow_uid(uid_t uid);
int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext);
int su_remove_allow_uid(uid_t uid);
int su_allow_uid_nums();
int su_allow_uids(int is_user, uid_t *out_uids, int out_num);
int su_allow_uid_profile(int is_user, uid_t uid, struct su_profile *profile);
int su_reset_path(const char *path);
const char *su_get_path();
void sucompat_init(void);

int get_ap_mod_exclude(uid_t uid);
int set_ap_mod_exclude(uid_t uid, int exclude);
int list_ap_mod_exclude(uid_t *uids, int len);

/* Register / unregister the fstatat/faccessat path-probe hooks.
 * Called from the post-fs-data event handler so the hooks are only
 * present when /data/adb is available. */
void sucompat_register_path_probe_hooks(void);
void sucompat_unregister_path_probe_hooks(void);

/* Supercall handler: control a feature by name.
 * state: 1=enable, 0=disable, -1=query current state. */
long kp_control_feature_sc(const char __user *uname, int state);

#endif
