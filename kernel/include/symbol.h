/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_SYMBOL_H_
#define _KP_SYMBOL_H_

#define KP_SYMBOL_LEN 32

// todo: name len
typedef struct
{
    unsigned long addr;
    unsigned long hash;
    const char name[KP_SYMBOL_LEN];
} kp_symbol_t;

#define _KP_EXPORT_SYMBOL(sym)                                 \
    static kp_symbol_t __kp_symbol_##sym __attribute__((used)) \
    __attribute__((section(".kp.symbol"))) = { .name = #sym, .addr = (unsigned long)&sym, .hash = 0 }

#define KP_EXPORT_SYMBOL(sym) _KP_EXPORT_SYMBOL(sym)

extern unsigned long link_base_addr;
extern unsigned long runtime_base_addr;

unsigned long symbol_lookup_name(const char *name);

static inline unsigned long link2runtime(unsigned long addr)
{
    return addr - link_base_addr + runtime_base_addr;
}

#endif