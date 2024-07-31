/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 1f2003d5. All Rights Reserved.
 * Copyright (C) 2024 sekaiacg. All Rights Reserved.
 */

#ifndef _KP_SEPOLICY_FLAGS_H_
#define _KP_SEPOLICY_FLAGS_H_

#include <linux/string.h>

#define SELINUX_MAGIC 0xf97cff8c
#define POLICYDB_MAGIC SELINUX_MAGIC
#define POLICYDB_STRING "SE Linux"

#define POLICYDB_CONFIG_MLS 1
#define POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE (1 << 31)
#define POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH (1 << 30)

/*
 * config offset:
 *   __le32(POLICYDB_MAGIC) + __le32(POLICYDB_STRING_LEN) +
 *   char[POLICYDB_STRING_LEN] + __le32(policyvers)
 */
#define POLICYDB_CONFIG_OFFSET (2 * sizeof(__le32) + strlen(POLICYDB_STRING) + sizeof(__le32))

struct _policy_file
{
    char *data;
    size_t len;
};

struct _policydb
{
    int mls_enabled;
    int android_netlink_route;
    int android_netlink_getneigh;
};

#endif