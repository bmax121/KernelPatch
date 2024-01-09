/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <symbol.h>
#include <log.h>
#include <stdint.h>

#include "start.h"
#include "setup.h"

extern void _kp_symbol_start();
extern void _kp_symbol_end();
static uint64_t symbol_start = 0;
static uint64_t symbol_end = 0;
static unsigned long link_base_addr = (unsigned long)_link_base;
static unsigned long runtime_base_addr = 0;

// DJB2
static unsigned long sym_hash(const char *str)
{
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

int local_strcmp(const char *s1, const char *s2)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (1) {
        d = (int)(ch = *c1++) - (int)*c2++;
        if (d || !ch) break;
    }
    return d;
}

unsigned long symbol_lookup_name(const char *name)
{
    unsigned long hash = sym_hash(name);
    for (uint64_t addr = symbol_start; addr < symbol_end; addr += sizeof(kp_symbol_t)) {
        kp_symbol_t *symbol = (kp_symbol_t *)addr;
        if (hash == symbol->hash && !local_strcmp(name, symbol->name)) {
            return symbol->addr;
        }
    }
    return 0;
}

int symbol_init()
{
    runtime_base_addr = (unsigned long)_link_base;
    symbol_start = (uint64_t)_kp_symbol_start;
    symbol_end = (uint64_t)_kp_symbol_end;
    log_boot("Symbol: %llx, %llx\n", symbol_start, symbol_end);
    log_boot("Symbol link: %llx, runtime: %llx\n", link_base_addr, runtime_base_addr);
    for (uint64_t addr = symbol_start; addr < symbol_end; addr += sizeof(kp_symbol_t)) {
        kp_symbol_t *symbol = (kp_symbol_t *)addr;
        symbol->addr = symbol->addr - link_base_addr + runtime_base_addr;
        symbol->hash = sym_hash(symbol->name);
    }
    return 0;
}