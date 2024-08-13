/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <user_event.h>

#include <log.h>

int report_user_event(const char *event, const char *args)
{
    logki("user report event: %s, args: %s\n", event, args);
    return 0;
}