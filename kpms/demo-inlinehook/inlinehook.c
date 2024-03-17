/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>

KPM_NAME("kpm-inline-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module Inline Hook Example");

int __noinline add(int a, int b)
{
    logkd("origin add called\n");
    int ret = a + b;
    return ret;
}

void before_add(hook_fargs2_t *args, void *udata)
{
    logkd("before add arg0: %d, arg1: %d\n", (int)args->arg0, (int)args->arg1);
}

void after_add(hook_fargs2_t *args, void *udata)
{
    logkd("after add arg0: %d, arg1: %d, ret: %d\n", (int)args->arg0, (int)args->arg1, (int)args->ret);
    args->ret = 100;
}

static long inline_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    logkd("kpm inline-hook-demo init\n");

    int a = 20;
    int b = 10;

    int ret = add(a, b);
    logkd("%d + %d = %d\n", a, b, ret);

    hook_err_t err = hook_wrap2((void *)add, before_add, after_add, 0);
    logkd("hook err: %d\n", err);

    ret = add(a, b);
    logkd("%d + %d = %d\n", a, b, ret);

    return 0;
}

static long inline_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm control, args: %s\n", args);
    return 0;
}

static long inline_hook_demo_exit(void *__user reserved)
{
    unhook((void *)add);

    int a = 20;
    int b = 10;

    int ret = add(a, b);
    logkd("%d + %d = %d\n", a, b, ret);

    logkd("kpm inline-hook-demo  exit\n");
}

KPM_INIT(inline_hook_demo_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_demo_exit);