/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 1f2003d5. All Rights Reserved.
 * Copyright (C) 2024 sekaiacg. All Rights Reserved.
 */

#include "sepolicy_flags.h"

#include <ksyms.h>
#include <uapi/scdefs.h>
#include <linux/spinlock.h>
#include <linux/capability.h>
#include <linux/security.h>
#include <asm/current.h>
#include <asm/thread_info.h>
#include <uapi/asm-generic/errno.h>
#include <hook.h>
#include <linux/string.h>
#include <predata.h>

/*
 * @see: https://android-review.googlesource.com/c/kernel/common/+/3009995
 */

static void before_policydb_write(hook_fargs2_t *args, void *udata)
{
    struct _policy_file *fp = (struct _policy_file *)args->arg1;
    args->local.data0 = (uint64_t)fp->data;
}

static void after_policydb_write(hook_fargs2_t *args, void *udata)
{
    struct _policydb *p = (struct _policydb *)args->arg0;
    char *data = (char *)args->local.data0;

    if (!args->ret) {
        __le32 *config = (__le32 *)(data + POLICYDB_CONFIG_OFFSET);
        __le32 before_config = *config;
        bool android_netlink_route_exists = before_config & POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
        bool android_netlink_getneigh_exists = before_config & POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
        if (p->android_netlink_route == 1 && !android_netlink_route_exists) {
            *config |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
        }
        if (p->android_netlink_getneigh == 1 && !android_netlink_getneigh_exists) {
            *config |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
        }
    }
}

int android_sepolicy_flags_fix()
{
    unsigned long policydb_write_addr = kallsyms_lookup_name("policydb_write");

    if (likely(policydb_write_addr)) {
        hook_err_t err = hook_wrap2((void *)policydb_write_addr, before_policydb_write, after_policydb_write, 0);

        if (unlikely(err != HOOK_NO_ERR)) {
            log_boot("hook policydb_write_addr: %llx, error: %d\n", policydb_write_addr, err);
            return -1;
        }
    }

    return 0;
}
