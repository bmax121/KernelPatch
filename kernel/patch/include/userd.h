/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_USERD_H_
#define _KP_USERD_H_

#include <ktypes.h>

int load_ap_package_config(void);

#ifdef ANDROID
int refresh_trusted_manager_uid(void);
int refresh_trusted_manager_state(void);
int is_trusted_manager_uid(uid_t uid);
uid_t get_trusted_manager_uid(void);

#endif

#endif
