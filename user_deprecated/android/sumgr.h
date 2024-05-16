/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KPU_ANDROID_SUMGR_H_
#define _KPU_ANDROID_SUMGR_H_

#include <unistd.h>

#ifdef __cplusplus
extern "C"
{
#endif

    int sumgr_main(int argc, char **argv);

    int su_grant(const char *key, uid_t uid, uid_t to_uid, const char *scontext);
    int su_revoke(const char *key, uid_t uid);
    int su_nums(const char *key);
    int su_list(const char *key);
    int su_profile(const char *key, uid_t uid);
    int su_reset_path(const char *key, const char *path);
    int su_get_path(const char *key);

#ifdef __cplusplus
}
#endif

#endif