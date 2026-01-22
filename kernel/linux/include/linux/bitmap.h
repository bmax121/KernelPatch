#ifndef __LINUX_BITMAP_H
#define __LINUX_BITMAP_H

#include <linux/bitops.h>

#define BITS_PER_LONG 64

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

static inline unsigned int __bitmap_weight(const unsigned long *bitmap, int bits)
{
    unsigned int k, w = 0, lim = bits / BITS_PER_LONG;

    for (k = 0; k < lim; k++)
        w += hweight_long(bitmap[k]);

    if (bits % BITS_PER_LONG) w += hweight_long(bitmap[k] & BITMAP_LAST_WORD_MASK(bits));

    return w;
}

#endif