/* SPDX-License-Identifier: GPL-2.0 */
/*
 * An extensible bitmap is a bitmap that supports an
 * arbitrary number of bits.  Extensible bitmaps are
 * used to represent sets of values, such as types,
 * roles, categories, and classes.
 *
 * Each extensible bitmap is implemented as a linked
 * list of bitmap nodes, where each bitmap node has
 * an explicitly specified starting bit position within
 * the total bitmap.
 *
 * Author : Stephen Smalley, <sds@tycho.nsa.gov>
 */
#ifndef _SS_EBITMAP_H_
#define _SS_EBITMAP_H_

#include <net/netlabel.h>
#include <ktypes.h>

#define EBITMAP_NODE_SIZE 64

#define EBITMAP_UNIT_NUMS ((EBITMAP_NODE_SIZE - sizeof(void *) - sizeof(u32)) / sizeof(unsigned long))
#define EBITMAP_UNIT_SIZE BITS_PER_LONG
#define EBITMAP_SIZE (EBITMAP_UNIT_NUMS * EBITMAP_UNIT_SIZE)
#define EBITMAP_BIT 1ULL
#define EBITMAP_SHIFT_UNIT_SIZE(x) (((x) >> EBITMAP_UNIT_SIZE / 2) >> EBITMAP_UNIT_SIZE / 2)

struct ebitmap_node
{
    struct ebitmap_node *next;
    unsigned long maps[EBITMAP_UNIT_NUMS];
    u32 startbit;
};

struct ebitmap
{
    struct ebitmap_node *node; /* first node in the bitmap */
    u32 highbit; /* highest position in the total bitmap */
};

#define ebitmap_length(e) ((e)->highbit)

#define ebitmap_for_each_positive_bit(e, n, bit) \
    for (bit = ebitmap_start_positive(e, &n); bit < ebitmap_length(e); bit = ebitmap_next_positive(e, &n, bit))

#define EBITMAP_NODE_INDEX(node, bit) (((bit) - (node)->startbit) / EBITMAP_UNIT_SIZE)
#define EBITMAP_NODE_OFFSET(node, bit) (((bit) - (node)->startbit) % EBITMAP_UNIT_SIZE)

#define ebitmap_for_each_positive_bit(e, n, bit) \
    for (bit = ebitmap_start_positive(e, &n); bit < ebitmap_length(e); bit = ebitmap_next_positive(e, &n, bit))

extern int kfunc_def(ebitmap_cmp)(struct ebitmap *e1, struct ebitmap *e2);
extern int kfunc_def(ebitmap_cpy)(struct ebitmap *dst, struct ebitmap *src);
extern int kfunc_def(ebitmap_and)(struct ebitmap *dst, struct ebitmap *e1, struct ebitmap *e2);
extern int kfunc_def(ebitmap_contains)(struct ebitmap *e1, struct ebitmap *e2, u32 last_e2bit);
extern int kfunc_def(ebitmap_get_bit)(struct ebitmap *e, unsigned long bit);
extern int kfunc_def(ebitmap_set_bit)(struct ebitmap *e, unsigned long bit, int value);
extern void kfunc_def(ebitmap_destroy)(struct ebitmap *e);
extern int kfunc_def(ebitmap_read)(struct ebitmap *e, void *fp);
extern int kfunc_def(ebitmap_write)(struct ebitmap *e, void *fp);
extern u32 kfunc_def(ebitmap_hash)(const struct ebitmap *e, u32 hash);

int ebitmap_cmp(struct ebitmap *e1, struct ebitmap *e2)
{
    kfunc_call(ebitmap_cmp, e1, e2);
    kfunc_not_found();
    return 0;
}
int ebitmap_cpy(struct ebitmap *dst, struct ebitmap *src)
{
    kfunc_call(ebitmap_cpy, dst, src);
    kfunc_not_found();
    return 0;
}
int ebitmap_and(struct ebitmap *dst, struct ebitmap *e1, struct ebitmap *e2)
{
    kfunc_call(ebitmap_and, dst, e1, e2);
    kfunc_not_found();
    return 0;
}
int ebitmap_contains(struct ebitmap *e1, struct ebitmap *e2, u32 last_e2bit)
{
    kfunc_call(ebitmap_contains, e1, e2, last_e2bit);
    kfunc_not_found();
    return 0;
}
int ebitmap_get_bit(struct ebitmap *e, unsigned long bit)
{
    kfunc_call(ebitmap_get_bit, e, bit);
    kfunc_not_found();
    return 0;
}
int ebitmap_set_bit(struct ebitmap *e, unsigned long bit, int value)
{
    kfunc_call(ebitmap_set_bit, e, bit, value);
    kfunc_not_found();
    return 0;
}
void ebitmap_destroy(struct ebitmap *e)
{
    kfunc_call(ebitmap_destroy, e);
    kfunc_not_found();
    return 0;
}
int ebitmap_read(struct ebitmap *e, void *fp)
{
    kfunc_call(ebitmap_read, e, fp);
    kfunc_not_found();
    return 0;
}
int ebitmap_write(struct ebitmap *e, void *fp)
{
    kfunc_call(ebitmap_write, e, fp);
    kfunc_not_found();
    return 0;
}
u32 ebitmap_hash(const struct ebitmap *e, u32 hash)
{
    kfunc_call(ebitmap_hash, e, hash);
    kfunc_not_found();
    return 0;
}

#endif /* _SS_EBITMAP_H_ */