/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A security identifier table (sidtab) is a lookup table
 * of security context structures indexed by SID value.
 *
 * Original author: Stephen Smalley, <sds@tycho.nsa.gov>
 * Author: Ondrej Mosnacek, <omosnacek@gmail.com>
 *
 * Copyright (C) 2018 Red Hat, Inc.
 */
#ifndef _SS_SIDTAB_H_
#define _SS_SIDTAB_H_

#include <ktypes.h>
#include "context.h"

struct sidtab_node // 3.7 -
{
    u32 sid; /* security identifier */
    struct context context; /* security context structure */
    struct sidtab_node *next;
};

struct sidtab_entry
{
    u32 sid;
    u32 hash;
    struct context context;
#if CONFIG_SECURITY_SELINUX_SID2STR_CACHE_SIZE > 0
    struct sidtab_str_cache __rcu *cache;
#endif
    struct hlist_node _list;
};

union sidtab_entry_inner
{
    struct sidtab_node_inner *ptr_inner;
    struct sidtab_node_leaf *ptr_leaf;
};

/* align node size to page boundary */
#define SIDTAB_NODE_ALLOC_SHIFT PAGE_SHIFT
#define SIDTAB_NODE_ALLOC_SIZE PAGE_SIZE

#define size_to_shift(size) ((size) == 1 ? 1 : (const_ilog2((size)-1) + 1))

#define SIDTAB_INNER_SHIFT (SIDTAB_NODE_ALLOC_SHIFT - size_to_shift(sizeof(union sidtab_entry_inner)))
#define SIDTAB_INNER_ENTRIES ((size_t)1 << SIDTAB_INNER_SHIFT)
#define SIDTAB_LEAF_ENTRIES (SIDTAB_NODE_ALLOC_SIZE / sizeof(struct sidtab_entry))

#define SIDTAB_MAX_BITS 32
#define SIDTAB_MAX U32_MAX
/* ensure enough tree levels for SIDTAB_MAX entries */
#define SIDTAB_MAX_LEVEL DIV_ROUND_UP(SIDTAB_MAX_BITS - size_to_shift(SIDTAB_LEAF_ENTRIES), SIDTAB_INNER_SHIFT)

struct sidtab_isid_entry
{
    int set;
    struct sidtab_entry entry;
};

struct sidtab;

struct sidtab_convert_params
{
    int (*func)(struct context *oldc, struct context *newc, void *args, gfp_t gfp_flags);
    void *args;
    struct sidtab *target;
};

#define SIDTAB_HASH_BITS CONFIG_SECURITY_SELINUX_SIDTAB_HASH_BITS
#define SIDTAB_HASH_BUCKETS (1 << SIDTAB_HASH_BITS)

#endif /* _SS_SIDTAB_H_ */
