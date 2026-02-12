/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023-2026 bmax121. All Rights Reserved.
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <kputils.h>
#include <common.h>
#include <linux/string.h>

///< The name of the module, each KPM must have a unique name.
KPM_NAME("kpm-inline-hook-demo");

///< The version of the module.
KPM_VERSION("1.1.0");

///< The license type.
KPM_LICENSE("GPL v2");

///< The author.
KPM_AUTHOR("bmax121");

///< The description.
KPM_DESCRIPTION("KernelPatch Module Inline Hook Example (Revived)");

/**
 * @brief Simple function to be hooked.
 * @note __noinline is required to ensure the function is not inlined by the compiler.
 * @param a First operand
 * @param b Second operand
 * @return Sum of a and b (or 100 if hooked and modified)
 */
int __noinline add(int a, int b)
{
    logkd("origin add called: %d, %d\n", a, b);
    return a + b;
}

/**
 * @brief Hook callback called before the target function.
 * @param args Contains function arguments (arg0, arg1, ...)
 * @param udata User data passed to hook_wrap
 */
void before_add(hook_fargs2_t *args, void *udata)
{
    pr_info("kpm-inline-hook-demo: [BEFORE] add(%d, %d)\n", (int)args->arg0, (int)args->arg1);
}

/**
 * @brief Hook callback called after the target function.
 * @param args Contains function arguments and return value (ret)
 * @param udata User data passed to hook_wrap
 */
void after_add(hook_fargs2_t *args, void *udata)
{
    pr_info("kpm-inline-hook-demo: [AFTER] add ret: %d -> 100\n", (int)args->ret);
    // Demonstrate return value modification
    args->ret = 100;
}

/**
 * @brief Module initialization
 * @param args Arguments passed when loading the module
 * @param event The event that triggered the load
 * @param reserved Reserved for future use
 * @return 0 on success, non-zero on error
 */
static long inline_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("kpm-inline-hook-demo: initializing... (event: %s, args: %s)\n", event, args);

    int a = 20, b = 10;
    int ret = add(a, b);
    pr_info("kpm-inline-hook-demo: add(%d, %d) = %d (expected 30)\n", a, b, ret);

    hook_err_t err = hook_wrap2((void *)add, before_add, after_add, 0);
    if (err != HOOK_NO_ERR) {
        pr_err("kpm-inline-hook-demo: failed to hook add() (err: %d)\n", err);
        return -1;
    }
    pr_info("kpm-inline-hook-demo: hook installed successfully\n");

    ret = add(a, b);
    pr_info("kpm-inline-hook-demo: add(%d, %d) = %d (expected 100)\n", a, b, ret);

    return 0;
}

/**
 * @brief Module control interface 0
 * @param args Input arguments from userspace
 * @param out_msg Output message buffer to userspace
 * @param outlen Output buffer length
 * @return 0 on success, negative on error
 */
static long inline_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm-inline-hook-demo: control0 called with args: %s\n", args);
    
    if (args && !strcmp(args, "unhook")) {
        hook_unwrap((void *)add, before_add, after_add);
        pr_info("kpm-inline-hook-demo: unhooked add() manually\n");
        return 0;
    } else if (args && !strcmp(args, "hook")) {
        hook_err_t err = hook_wrap2((void *)add, before_add, after_add, 0);
        pr_info("kpm-inline-hook-demo: re-hooking add() (err: %d)\n", err);
        return (long)err;
    }
    
    return 0;
}

/**
 * @brief Module exit
 * @param reserved Reserved for future use
 * @return 0 on success
 */
static long inline_hook_demo_exit(void *__user reserved)
{
    pr_info("kpm-inline-hook-demo: exiting...\n");
    
    // Cleanup hooks
    hook_unwrap((void *)add, before_add, after_add);

    int a = 20, b = 10;
    int ret = add(a, b);
    pr_info("kpm-inline-hook-demo: add(%d, %d) = %d (expected 30 after unhook)\n", a, b, ret);
    
    return 0;
}

KPM_INIT(inline_hook_demo_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_demo_exit);