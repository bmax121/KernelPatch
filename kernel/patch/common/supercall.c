/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ktypes.h>

#ifdef ANDROID
#include <userd.h>
#endif

int is_trusted_manager_uid(uid_t uid)
{
    #ifdef ANDROID
    return is_trusted_manager_uid_android(uid);
    #endif
    return 0;
}
