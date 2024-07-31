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
 * see: https://android-review.googlesource.com/c/kernel/common/+/3009995
 *
 */

static int (*policydb_write_backup)(struct _policydb *p, struct _policy_file *fp) = 0;
static int policydb_write_replace(struct _policydb *p, struct _policy_file *fp)
{
    char *data = fp->data;
    int ret = policydb_write_backup(p, fp);
    if (!ret) {
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
    return ret;
}

int android_sepolicy_flags_init()
{
    unsigned long policydb_write_addr = get_preset_patch_sym()->policydb_write;
    if (likely(policydb_write_addr)) {
        hook_err_t err = hook((void *)policydb_write_addr, (void *)policydb_write_replace, (void **)&policydb_write_backup);
        if (unlikely(err != HOOK_NO_ERR)) {
            log_boot("hook policydb_write_addr: %llx, error: %d\n", policydb_write_addr, err);
            return -1;
        }
    }

    return 0;
}
