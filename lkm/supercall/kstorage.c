// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 *
 * Ported from kernel/patch/common/kstorage.c.
 */
#include "kstorage.h"

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "../include/kp_lkm.h"

#define KSTORAGE_HASH_BITS 8
#define KSTORAGE_NBUCKETS (1 << KSTORAGE_HASH_BITS)

static int used_max_group = -1;
static struct hlist_head kstorage_groups[KP_KSTORAGE_MAX_GROUP_NUM][KSTORAGE_NBUCKETS];
static spinlock_t kstorage_glocks[KP_KSTORAGE_MAX_GROUP_NUM];
static int group_sizes[KP_KSTORAGE_MAX_GROUP_NUM] = { 0 };
static spinlock_t used_max_group_lock;

static inline struct hlist_head *kstorage_bucket(int gid, long did)
{
	unsigned long h = (unsigned long)did * 0x9e3779b97f4a7c15UL;
	return &kstorage_groups[gid][h >> (64 - KSTORAGE_HASH_BITS)];
}

static void reclaim_callback(struct rcu_head *rcu)
{
	struct kp_kstorage *ks = container_of(rcu, struct kp_kstorage, rcu);
	kvfree(ks);
}

int kp_kstorage_alloc_group(void)
{
	int gid;
	spin_lock(&used_max_group_lock);
	if (used_max_group + 1 >= KP_KSTORAGE_MAX_GROUP_NUM) {
		spin_unlock(&used_max_group_lock);
		return -1;
	}
	used_max_group++;
	gid = used_max_group;
	spin_unlock(&used_max_group_lock);
	return gid;
}

int kp_kstorage_group_size(int gid)
{
	if (gid < 0 || gid >= KP_KSTORAGE_MAX_GROUP_NUM)
		return -ENOENT;
	return READ_ONCE(group_sizes[gid]);
}

int kp_kstorage_write(int gid, long did, void *data, int offset, int len, bool data_is_user)
{
	int rc = -ENOENT;
	struct hlist_head *bucket;
	spinlock_t *lock;
	struct kp_kstorage *pos, *old = NULL;
	struct kp_kstorage *new;

	if (gid < 0 || gid >= KP_KSTORAGE_MAX_GROUP_NUM)
		return rc;

	bucket = kstorage_bucket(gid, did);
	lock = &kstorage_glocks[gid];

	/* Do the potentially-sleeping allocation/copy before the RCU critical
	 * section (vmalloc()/memdup_user() may sleep). */
	new = vmalloc(sizeof(*new) + len);
	if (!new)
		return -ENOMEM;
	new->gid = gid;
	new->did = did;
	new->dlen = 0;
	if (data_is_user) {
		void *drc = memdup_user(data + offset, len);
		if (IS_ERR(drc)) {
			vfree(new);
			return PTR_ERR(drc);
		}
		memcpy(new->data, drc, len);
		kfree(drc);
	} else {
		memcpy(new->data, data + offset, len);
	}
	new->dlen = len;

	rcu_read_lock();

	hlist_for_each_entry_rcu(pos, bucket, hnode) {
		if (pos->did == did) {
			old = pos;
			break;
		}
	}

	spin_lock(lock);
	if (old) {
		hlist_replace_rcu(&old->hnode, &new->hnode);
	} else {
		hlist_add_head_rcu(&new->hnode, bucket);
		group_sizes[gid]++;
	}
	spin_unlock(lock);

	rcu_read_unlock();

	if (old)
		call_rcu(&old->rcu, reclaim_callback);
	return 0;
}

const struct kp_kstorage *kp_kstorage_get(int gid, long did)
{
	struct hlist_head *bucket;
	struct kp_kstorage *pos;

	if (gid < 0 || gid >= KP_KSTORAGE_MAX_GROUP_NUM)
		return ERR_PTR(-ENOENT);

	bucket = kstorage_bucket(gid, did);

	hlist_for_each_entry_rcu(pos, bucket, hnode) {
		if (pos->did == did)
			return pos;
	}

	return ERR_PTR(-ENOENT);
}

int kp_kstorage_read(int gid, long did, void *data, int offset, int len, bool data_is_user)
{
	const struct kp_kstorage *pos;
	int min_len;
	int rc = 0;

	rcu_read_lock();

	pos = kp_kstorage_get(gid, did);
	if (IS_ERR(pos)) {
		rcu_read_unlock();
		return PTR_ERR(pos);
	}

	min_len = pos->dlen - offset > len ? len : pos->dlen - offset;
	if (min_len < 0)
		min_len = 0;

	if (data_is_user) {
		if (copy_to_user(data, pos->data + offset, min_len))
			rc = -EFAULT;
	} else {
		memcpy(data, pos->data + offset, min_len);
	}

	rcu_read_unlock();
	return rc;
}

int kp_kstorage_list_ids(int gid, long *ids, int idslen, bool data_is_user)
{
	struct kp_kstorage *pos;
	int cnt = 0;
	int rc = 0;

	if (gid < 0 || gid >= KP_KSTORAGE_MAX_GROUP_NUM)
		return -ENOENT;

	rcu_read_lock();

	for (int b = 0; b < KSTORAGE_NBUCKETS; b++) {
		hlist_for_each_entry_rcu(pos, &kstorage_groups[gid][b], hnode) {
			if (cnt >= idslen)
				goto out;
			if (data_is_user) {
				if (copy_to_user(ids + cnt, &pos->did, sizeof(pos->did))) {
					rc = -EFAULT;
					goto out;
				}
			} else {
				memcpy(ids + cnt, &pos->did, sizeof(pos->did));
			}
			cnt++;
		}
	}

out:
	rcu_read_unlock();
	return rc ? rc : cnt;
}

int kp_kstorage_remove(int gid, long did)
{
	struct hlist_head *bucket;
	spinlock_t *lock;
	struct kp_kstorage *pos;

	if (gid < 0 || gid >= KP_KSTORAGE_MAX_GROUP_NUM)
		return -ENOENT;

	bucket = kstorage_bucket(gid, did);
	lock = &kstorage_glocks[gid];

	spin_lock(lock);

	hlist_for_each_entry_rcu(pos, bucket, hnode) {
		if (pos->did == did) {
			hlist_del_rcu(&pos->hnode);
			spin_unlock(lock);
			group_sizes[gid]--;
			call_rcu(&pos->rcu, reclaim_callback);
			return 0;
		}
	}

	spin_unlock(lock);
	return -ENOENT;
}

int kp_kstorage_init(void)
{
	for (int i = 0; i < KP_KSTORAGE_MAX_GROUP_NUM; i++) {
		for (int b = 0; b < KSTORAGE_NBUCKETS; b++)
			INIT_HLIST_HEAD(&kstorage_groups[i][b]);
		spin_lock_init(&kstorage_glocks[i]);
	}
	spin_lock_init(&used_max_group_lock);
	return 0;
}
