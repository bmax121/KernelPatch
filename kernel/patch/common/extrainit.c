/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
#include <extrainit.h>
#include <predata.h>
#include <log.h>
#include <linux/string.h>
#include <module.h>

static int extra_load_kpm_callback(const patch_extra_item_t *extra, const char *args, const void *data, void *udata)
{
    const char *event = (const char *)udata;
    if (extra->type == EXTRA_TYPE_KPM) {
        if (!strcmp(event, extra->event) || (!extra->event[0] && !strcmp(EXTRA_EVENT_KPM_DEFAULT, event))) {
            int rc = load_module(data, extra->con_size, args, event, 0);
            log_boot("%s loading extra kpm return: %d\n", event, rc);
        }
    }
    return 0;
}

int extra_load_kpm(const char *event)
{
    on_each_extra_item(extra_load_kpm_callback, (void *)event);
    return 0;
}
