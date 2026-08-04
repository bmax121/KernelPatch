/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 *
 * Kernel-side key-value storage. Ported from kernel/patch/common/kstorage.c.
 * Pure vmalloc + RCU hash table + spinlocks — no VFS dependency, fully
 * portable to the LKM. Used to persist the SU allowlist (group 0).
 */
#ifndef _KP_LKM_KSTORAGE_H_
#define _KP_LKM_KSTORAGE_H_
#include <linux/types.h>

#define KP_KSTORAGE_MAX_GROUP_NUM 4

struct kp_kstorage
{
	struct hlist_node hnode;
	struct rcu_head rcu;
	int gid;
	long did;
	int dlen;
	char data[0];
};

/* Allocate the next free group id (0..KP_KSTORAGE_MAX_GROUP_NUM-1). */
int kp_kstorage_alloc_group(void);

int kp_kstorage_group_size(int gid);

/* Write/overwrite an entry. data_is_user selects copy_from_user vs memcpy. */
int kp_kstorage_write(int gid, long did, void *data, int offset, int len, bool data_is_user);

/* Lookup — must be called within rcu_read_lock. */
const struct kp_kstorage *kp_kstorage_get(int gid, long did);

int kp_kstorage_read(int gid, long did, void *data, int offset, int len, bool data_is_user);

/* Returns count written, or negative error. */
int kp_kstorage_list_ids(int gid, long *ids, int idslen, bool data_is_user);

int kp_kstorage_remove(int gid, long did);

int kp_kstorage_init(void);

#endif /* _KP_LKM_KSTORAGE_H_ */
