/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_STRINGHASH_H
#define __LINUX_STRINGHASH_H

/* Hash courtesy of the R5 hash in reiserfs modulo sign bits */
#define init_name_hash(salt) (unsigned long)(salt)

/* partial hash update function. Assume roughly 4 bits per character */
static inline unsigned long partial_name_hash(unsigned long c, unsigned long prevhash)
{
    return (prevhash + (c << 4) + (c >> 4)) * 11;
}

#endif