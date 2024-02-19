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

KPM_NAME("phys-access");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("Expose APIs for access process physical memory.");

static int init(const char *args, void *__user reserved)
{
    return 0;
}

static int control(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

static int exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(init);
KPM_CTL(control);
KPM_EXIT(exit);
