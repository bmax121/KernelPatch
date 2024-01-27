/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
#include <extrainit.h>
#include <predata.h>
#include <log.h>
#include <module.h>

static int extra_callback(const patch_extra_item_t *extra, const char *args, const void *data, void *udata)
{
    int *num = (int *)udata;
    if (extra->type == EXTRA_TYPE_KPM) {
        int rc = load_module(data, extra->con_size, args, 0);
        log_boot("loading extra %d kpm return: %d\n", *num, rc);
    }
    (*num)++;
    return 0;
}

int extra_init()
{
    int num = 0;
    on_each_extra_item(extra_callback, &num);
    return 0;
}
