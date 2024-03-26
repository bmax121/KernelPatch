/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_SUCOMPAT_H_
#define _KP_SUCOMPAT_H_

#include <ktypes.h>
#include <uapi/scdefs.h>

struct allow_uid
{
    uid_t uid;
    struct su_profile profile;
    struct list_head list;
    struct rcu_head rcu;
};

struct su_profile profile_su_allow_uid(uid_t uid);
int is_su_allow_uid(uid_t uid);

#endif
