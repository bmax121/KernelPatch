/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <user_event.h>
#include <userd.h>
#include <baselib.h>
#include <log.h>

int report_user_event(const char *event, const char *args)
{
    const char *safe_event = event ? event : "";
    const char *safe_args = args ? args : "";

    #ifdef ANDROID
    if (lib_strcmp(safe_event, "post-fs-data") == 0 && lib_strcmp(safe_args, "before") == 0) {
        logki("post-fs-data before event received, loading ap package config ...\n");
        load_ap_package_config();
    }
    #endif
    logki("user report event: %s, args: %s\n", safe_event, safe_args);
    return 0;
}