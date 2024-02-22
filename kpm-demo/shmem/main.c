/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>

KPM_NAME("kpm-shmem");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("Share memory between processes");

/*
 * This module's main functionality is to map any address of any process to any other process. 
 * Of course, this means you can easily manipulate data of other processes. 
*/

static long init(const char *args, const char *event, void *__user reserved)
{
    return 0;
}

static long control0(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

static long exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(init);
KPM_CTL0(control0);
KPM_EXIT(exit);
