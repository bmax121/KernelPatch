#include <kstorage.h>

#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <compiler.h>
#include <stdbool.h>
#include <symbol.h>
#include <uapi/asm-generic/errno.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <kputils.h>

#define KSTRORAGE_MAX_GROUP_NUM 4

#define KSTORAGE_HASH_BITS 8
#define KSTORAGE_NBUCKETS (1 << KSTORAGE_HASH_BITS)

// static atomic64_t used_max_group = ATOMIC_INIT(0);
static int used_max_group = -1;
static struct hlist_head kstorage_groups[KSTRORAGE_MAX_GROUP_NUM][KSTORAGE_NBUCKETS];
static spinlock_t kstorage_glocks[KSTRORAGE_MAX_GROUP_NUM];
static int group_sizes[KSTRORAGE_MAX_GROUP_NUM] = { 0 };
static spinlock_t used_max_group_lock;

static inline struct hlist_head *kstorage_bucket(int gid, long did)
{
    unsigned long h = (unsigned long)did * 0x9e3779b97f4a7c15UL;
    return &kstorage_groups[gid][h >> (64 - KSTORAGE_HASH_BITS)];
}

static void reclaim_callback(struct rcu_head *rcu)
{
    struct kstorage *ks = container_of(rcu, struct kstorage, rcu);
    kvfree(ks);
}

int try_alloc_kstroage_group()
{
    spin_lock(&used_max_group_lock);
    if (used_max_group + 1 >= KSTRORAGE_MAX_GROUP_NUM) {
        spin_unlock(&used_max_group_lock);
        return -1;
    }
    used_max_group++;
    spin_unlock(&used_max_group_lock);
    return used_max_group;
}

int kstorage_group_size(int gid)
{
    if (gid < 0 || gid >= KSTRORAGE_MAX_GROUP_NUM) return -ENOENT;
    return group_sizes[gid];
}

int write_kstorage(int gid, long did, void *data, int offset, int len, bool data_is_user)
{
    int rc = -ENOENT;
    if (gid < 0 || gid >= KSTRORAGE_MAX_GROUP_NUM) return rc;

    struct hlist_head *bucket = kstorage_bucket(gid, did);
    spinlock_t *lock = &kstorage_glocks[gid];
    struct kstorage *pos = 0, *old = 0;

    // Do the potentially-sleeping allocation/copy before entering the RCU
    // read-side critical section below, since vmalloc()/memdup_user() may
    // sleep and must never be called with rcu_read_lock() held.
    struct kstorage *new = (struct kstorage *)vmalloc(sizeof(struct kstorage) + len);
    if (!new) {
        return -ENOMEM;
    }
    new->gid = gid;
    new->did = did;
    new->dlen = 0;
    if (data_is_user) {
        void *drc = memdup_user(data + offset, len);
        if (IS_ERR(drc)) {
            kvfree(new);
            return PTR_ERR(drc);
        }
        memcpy(new->data, drc, len);
        kvfree(drc);
    } else {
        memcpy(new->data, data + offset, len);
    }
    new->dlen = len;

    rcu_read_lock();

    hlist_for_each_entry_rcu(pos, bucket, hnode)
    {
        if (pos->did == did) {
            old = pos;
            break;
        }
    }

    spin_lock(lock);
    if (old) { // update
        hlist_replace_rcu(&old->hnode, &new->hnode);
    } else { // add new one
        hlist_add_head_rcu(&new->hnode, bucket);
        group_sizes[gid]++;
    }
    spin_unlock(lock);

    rcu_read_unlock();

    if (old) {
        bool async = true;
        if (async) {
            call_rcu(&old->rcu, reclaim_callback);
        } else {
            synchronize_rcu();
            kvfree(old);
        }
    }
    return 0;
}
KP_EXPORT_SYMBOL(write_kstorage);

const struct kstorage *get_kstorage(int gid, long did)
{
    if (gid < 0 || gid >= KSTRORAGE_MAX_GROUP_NUM) return ERR_PTR(-ENOENT);

    struct hlist_head *bucket = kstorage_bucket(gid, did);
    struct kstorage *pos = 0;

    hlist_for_each_entry_rcu(pos, bucket, hnode)
    {
        if (pos->did == did) {
            return pos;
        }
    }

    return ERR_PTR(-ENOENT);
}
KP_EXPORT_SYMBOL(get_kstorage);

int on_each_kstorage_elem(int gid, on_kstorage_cb cb, void *udata)
{
    if (gid < 0 || gid >= KSTRORAGE_MAX_GROUP_NUM) return -ENOENT;

    int rc = 0;

    struct kstorage *pos = 0;

    rcu_read_lock();

    for (int b = 0; b < KSTORAGE_NBUCKETS; b++) {
        hlist_for_each_entry_rcu(pos, &kstorage_groups[gid][b], hnode)
        {
            rc = cb(pos, udata);
            if (rc) goto out;
        }
    }

out:
    rcu_read_unlock();

    return rc;
}
KP_EXPORT_SYMBOL(on_each_kstorage_elem);

int read_kstorage(int gid, long did, void *data, int offset, int len, bool data_is_user)
{
    int rc = 0;
    rcu_read_lock();

    const struct kstorage *pos = get_kstorage(gid, did);

    if (IS_ERR(pos)) {
        rcu_read_unlock();
        return PTR_ERR(pos);
    }

    int min_len = pos->dlen - offset > len ? len : pos->dlen - offset;

    if (data_is_user) {
        int cplen = compat_copy_to_user(data, pos->data + offset, min_len);
        if (cplen <= 0) {
            logkfe("compat_copy_to_user error: %d", cplen);
            rc = cplen;
        }
    } else {
        memcpy(data, pos->data + offset, min_len);
    }

    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(read_kstorage);

int list_kstorage_ids(int gid, long *ids, int idslen, bool data_is_user)
{
    if (gid < 0 || gid >= KSTRORAGE_MAX_GROUP_NUM) return -ENOENT;

    int cnt = 0;
    int rc = 0;

    struct kstorage *pos = 0;

    rcu_read_lock();

    for (int b = 0; b < KSTORAGE_NBUCKETS; b++) {
        hlist_for_each_entry_rcu(pos, &kstorage_groups[gid][b], hnode)
        {
            if (cnt >= idslen) goto out;

            if (data_is_user) {
                int cplen = compat_copy_to_user(ids + cnt, &pos->did, sizeof(pos->did));
                if (cplen <= 0) {
                    logkfe("compat_copy_to_user error: %d", cplen);
                    rc = cplen;
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
KP_EXPORT_SYMBOL(list_kstorage_ids);

int remove_kstorage(int gid, long did)
{
    int rc = -ENOENT;
    if (gid < 0 || gid >= KSTRORAGE_MAX_GROUP_NUM) return rc;

    struct hlist_head *bucket = kstorage_bucket(gid, did);
    spinlock_t *lock = &kstorage_glocks[gid];
    struct kstorage *pos = 0;

    spin_lock(lock);

    hlist_for_each_entry_rcu(pos, bucket, hnode)
    {
        if (pos->did == did) {
            hlist_del_rcu(&pos->hnode);
            spin_unlock(lock);

            group_sizes[gid]--;

            bool async = true;
            if (async) {
                call_rcu(&pos->rcu, reclaim_callback);
            } else {
                synchronize_rcu();
                kvfree(pos);
            }
            return 0;
        }
    }

    spin_unlock(lock);

    return 0;
}
KP_EXPORT_SYMBOL(remove_kstorage);

int kstorage_init()
{
    for (int i = 0; i < KSTRORAGE_MAX_GROUP_NUM; i++) {
        for (int b = 0; b < KSTORAGE_NBUCKETS; b++) {
            INIT_HLIST_HEAD(&kstorage_groups[i][b]);
        }
        spin_lock_init(&kstorage_glocks[i]);
    }
    spin_lock_init(&used_max_group_lock);

    return 0;
}
