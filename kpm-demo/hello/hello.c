/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>

KPM_NAME("kpm-hello-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module Example");

int hello_init(const char *args, void *__user reserved)
{
    pr_info("kpm hello init, args: %s\n", args);
    pr_info("kernelpatch version: %x\n", kpver);
    return 0;
}

int hello_control(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm hello control, args: %s\n", args);
    char echo[] = "hello kpm\n";
    seq_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;
}

int hello_exit(void *__user reserved)
{
    pr_info("kpm hello exit\n");
    return 0;
}

KPM_INIT(hello_init);
KPM_CTL(hello_control);
KPM_EXIT(hello_exit);
