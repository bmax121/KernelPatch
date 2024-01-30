/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>

///< The name of the module, each KPM must has a unique name.
KPM_NAME("kpm-hello-demo");

///< The version of the module.
KPM_VERSION("1.0.0");

///< The license type.
KPM_LICENSE("GPL v2");

///< The author.
KPM_AUTHOR("bmax121");

///< The description.
KPM_DESCRIPTION("KernelPatch Module Example");

/**
 * @brief hello world initialization
 * @details 
 * 
 * @param args 
 * @param reserved 
 * @return int 
 */
static int hello_init(const char *args, void *__user reserved)
{
    pr_info("kpm hello init, args: %s\n", args);
    pr_info("kernelpatch version: %x\n", kpver);
    return 0;
}

static int hello_control(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm hello control, args: %s\n", args);
    char echo[64] = "echo: ";
    strncat(echo, args, 48);
    seq_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;
}

static int hello_exit(void *__user reserved)
{
    pr_info("kpm hello exit\n");
    return 0;
}

KPM_INIT(hello_init);
KPM_CTL(hello_control);
KPM_EXIT(hello_exit);
