/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_SYMBOL_LOOKUP_SCAN_H_
#define _KP_SYMBOL_LOOKUP_SCAN_H_

#include <kallsyms.h>

typedef int (*kp_symbol_scan_sprintf_t)(char *buf, const char *fmt, ...);

static inline int kp_symbol_scan_strcmp(const char *s1, const char *s2)
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

static inline char *kp_symbol_scan_strchr(char *s, int c)
{
    do {
        if (*s == (char)c) return s;
    } while (*s++);
    return 0;
}

static inline int kp_symbol_scan_parse_hex(const char *s, unsigned long *value)
{
    unsigned long v = 0;
    int n = 0;

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    while (1) {
        char ch = *s++;
        if (ch >= '0' && ch <= '9') {
            v = (v << 4) + (unsigned long)(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            v = (v << 4) + (unsigned long)(ch - 'a' + 10);
        } else if (ch >= 'A' && ch <= 'F') {
            v = (v << 4) + (unsigned long)(ch - 'A' + 10);
        } else {
            break;
        }
        n++;
    }
    *value = v;
    return n > 0;
}

static inline int kp_symbol_scan_parse_info(char *buf, unsigned long *offset, unsigned long *size)
{
    char *plus = kp_symbol_scan_strchr(buf, '+');
    char *slash;

    if (!plus) return 0;
    *plus++ = 0;

    slash = kp_symbol_scan_strchr(plus, '/');
    if (slash) {
        *slash++ = 0;
    }

    if (!kp_symbol_scan_parse_hex(plus, offset)) return 0;
    if (!slash) {
        *size = 0;
        return 1;
    }
    return kp_symbol_scan_parse_hex(slash, size);
}

static inline unsigned long kp_resolve_symbol_by_lookup_anchor(unsigned long kernel_va, unsigned long image_size,
                                                               unsigned long sprintf_offset,
                                                               unsigned long anchor_offset, const char *name)
{
    char buf[KSYM_NAME_LEN + 64];
    unsigned long addr;
    unsigned long func_start;
    unsigned long func_end;
    unsigned long offset;
    unsigned long size;
    unsigned long anchor_addr;
    kp_symbol_scan_sprintf_t kernel_sprintf;

    if (!anchor_offset || !sprintf_offset || !image_size) return 0;

    anchor_addr = kernel_va + anchor_offset;
    if (anchor_addr < kernel_va || anchor_addr >= kernel_va + image_size) return 0;

    kernel_sprintf = (kp_symbol_scan_sprintf_t)(kernel_va + sprintf_offset);
    addr = anchor_addr;

    for (int i = 0; i < 4096 && addr >= kernel_va && addr < kernel_va + image_size; i++) {
        kernel_sprintf(buf, "%pSb", (void *)addr);
        if (!kp_symbol_scan_parse_info(buf, &offset, &size) || !size || offset > addr - kernel_va) break;

        func_start = addr - offset;
        if (!kp_symbol_scan_strcmp(buf, name)) {
            return func_start - kernel_va;
        }

        func_end = func_start + size;
        if (func_end <= addr || func_end < func_start) break;
        addr = func_end + 4;
    }

    return 0;
}

#endif
