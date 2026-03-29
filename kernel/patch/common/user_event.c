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
    if (lib_strcmp(event, "post-fs-data") == 0 && lib_strcmp(args, "before") == 0) {
        logki("post-fs-data before event received, loading ap package config ...\n");
        load_ap_package_config();
    }
    logki("user report event: %s, args: %s\n", event, args);
    return 0;
}