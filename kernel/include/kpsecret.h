/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_SECRET_H_
#define _KP_SECRET_H_

/* Volatile stores keep credential erasure observable even under LTO. */
static inline void kp_secret_wipe(void *memory, unsigned long length)
{
    volatile unsigned char *p = memory;
    while (length--) *p++ = 0;
}

static inline int kp_secret_equal(const void *left, const void *right, unsigned long length)
{
    const unsigned char *a = left, *b = right;
    unsigned char difference = 0;
    while (length--) difference |= *a++ ^ *b++;
    return difference == 0;
}

static inline unsigned long kp_secret_length(const char *value, unsigned long capacity)
{
    unsigned long length = 0;
    if (!value) return capacity;
    while (length < capacity && value[length]) length++;
    return length;
}

#endif
