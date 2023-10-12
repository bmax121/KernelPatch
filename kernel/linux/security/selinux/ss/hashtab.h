/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A hash table (hashtab) maintains associations between
 * key values and datum values.  The type of the key values
 * and the type of the datum values is arbitrary.  The
 * functions for hash computation and key comparison are
 * provided by the creator of the table.
 *
 * Author : Stephen Smalley, <sds@tycho.nsa.gov>
 */

#ifndef _SS_HASHTAB_H_
#define _SS_HASHTAB_H_

#include <ktypes.h>
#include <ksyms.h>
#include <uapi/asm-generic/errno-base.h>

#define HASHTAB_MAX_NODES ((uint32_t)-1)

struct hashtab_key_params
{
    u32 (*hash)(const void *key); /* hash function */
    int (*cmp)(const void *key1, const void *key2);
    /* key comparison function */
};

struct hashtab_node
{
    void *key;
    void *datum;
    struct hashtab_node *next;
};

struct hashtab
{
    struct hashtab_node **htable; /* hash table */
    u32 size; /* number of slots in hash table */
    u32 nel; /* number of elements in hash table */
};

struct hashtab_lt590
{
    struct hashtab_node **htable; /* hash table */
    u32 size; /* number of slots in hash table */
    u32 nel; /* number of elements in hash table */
    u32 (*hash_value)(struct hashtab *h, const void *key);
    /* hash function */
    int (*keycmp)(struct hashtab *h, const void *key1, const void *key2);
    /* key comparison function */
};

struct hashtab_info
{
    u32 slots_used;
    u32 max_chain_len;
};

u32 filenametr_hash(const void *k);
int filenametr_cmp(const void *k1, const void *k2);

extern int kfunc_def(__hashtab_insert)(struct hashtab *h, struct hashtab_node **dst, void *key, void *datum);
/*
 * Inserts the specified (key, datum) pair into the specified hash table.
 *
 * Returns -ENOMEM on memory allocation error,
 * -EEXIST if there is already an entry with the same key,
 * -EINVAL for general errors or
  0 otherwise.
 */
static inline int hashtab_insert_inline(struct hashtab *h, void *key, void *datum, struct hashtab_key_params key_params)
{
    u32 hvalue;
    struct hashtab_node *prev, *cur;

    cond_resched();

    if (!h->size || h->nel == HASHTAB_MAX_NODES)
        return -EINVAL;

    hvalue = key_params.hash(key) & (h->size - 1);
    prev = 0;
    cur = h->htable[hvalue];
    while (cur) {
        int cmp = key_params.cmp(key, cur->key);

        if (cmp == 0)
            return -EEXIST;
        if (cmp < 0)
            break;
        prev = cur;
        cur = cur->next;
    }
    kfunc_call(__hashtab_insert, h, prev ? &prev->next : &h->htable[hvalue], key, datum);
    kfunc_not_found();
    return 0;
}

/*
 * Searches for the entry with the specified key in the hash table.
 *
 * Returns NULL if no entry has the specified key or
 * the datum of the entry otherwise.
 */
static inline void *hashtab_search_inline(struct hashtab *h, const void *key, struct hashtab_key_params key_params)
{
    u32 hvalue;
    struct hashtab_node *cur;

    if (!h->size)
        return 0;

    hvalue = key_params.hash(key) & (h->size - 1);
    cur = h->htable[hvalue];
    while (cur) {
        int cmp = key_params.cmp(key, cur->key);

        if (cmp == 0)
            return cur->datum;
        if (cmp < 0)
            break;
        cur = cur->next;
    }
    return 0;
}

extern int kfunc_def(hashtab_insert)(struct hashtab *h, void *key, void *datum, struct hashtab_key_params key_params);
extern void *kfunc_def(hashtab_search)(struct hashtab *h, const void *k);

static inline int hashtab_insert(struct hashtab *h, void *key, void *datum, struct hashtab_key_params key_params)
{
    kfunc_call(hashtab_insert, h, key, datum, key_params);
    return hashtab_insert_inline(h, key, datum, key_params);
    kfunc_not_found();
    return 0;
}

typedef int (*hashtab_insert_lt590_f)(struct hashtab *h, void *key, void *datum);
static inline int hashtab_insert_lt590(struct hashtab *h, void *key, void *datum)
{
    if (kfunc(hashtab_insert))
        return ((hashtab_insert_lt590_f)kfunc(hashtab_insert))(h, key, datum);
    kfunc_not_found();
    return 0;
}

static inline void *hashtab_search(struct hashtab *h, const void *k)
{
    kfunc_call(hashtab_search, h, k);
    kfunc_not_found();
    return 0;
}

#endif