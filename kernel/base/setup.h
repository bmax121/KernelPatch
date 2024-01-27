/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_SETUP_H_
#define _KP_SETUP_H_

#include "./preset.h"

#define STACK_SIZE 0x800

#ifndef __ASSEMBLY__

#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)

#define __section(s) __attribute__((section(#s)))
#define __noinline __attribute__((__noinline__))
#define __aligned(x) __attribute__((aligned(x)))

#endif

#ifndef __ASSEMBLY__
typedef struct
{
    // preset
    uint32_t paging_init_backup;
    uint32_t __;
    int64_t map_offset;
    int64_t start_offset;
    int64_t start_size;
    int64_t start_img_size;
    int64_t extra_size;
    int64_t alloc_size;
    uint64_t kernel_pa;
    uint64_t paging_init_relo;
    map_symbol_t map_symbol;
#ifdef MAP_DEBUG
    uint64_t printk_relo;
    uint64_t tmp0_offset;
    uint64_t tmp1_offset;
    char str_fmt_px[24];
#endif
    // local
    int64_t va1_bits;
    int64_t page_shift;
    uint64_t kimage_voffset;
    uint64_t linear_voffset;
} map_data_t;
#else
#define map_paging_init_backup_offset 0
#define map_map_offset_offset (map_paging_init_backup_offset + 8)
#define map_start_offset_offset (map_map_offset_offset + 8)
#define map_start_size_offset (map_start_offset_offset + 8)
#define map_start_img_size_offset (map_start_size_offset + 8)
#define map_extra_size_offset (map_start_img_size_offset + 8)
#define map_alloc_size_offset (map_extra_size_offset + 8)
#define map_kernel_pa_offset (map_alloc_size_offset + 8)
#define map_paging_init_relo_offset (map_kernel_pa_offset + 8)
#define map_map_symbol_offset (map_paging_init_relo_offset + 8)
#ifdef MAP_DEBUG
#define map_printk_relo_offset (map_map_symbol_offset + MAP_SYMBOL_SIZE)
#define map_tmp0_offset (map_printk_relo_offset + 8)
#define map_tmp1_offset (map_tmp0_offset + 8)
#define map_str_fmt_px_offset (map_tmp1_offset + 8)
#endif // MAP_DEBUG
#endif

#ifndef __ASSEMBLY__
typedef int (*start_f)(uint64_t kimage_voffset, uint64_t linear_voffset);
extern void _start_kernel();
extern void _paging_init();
extern void _link_base();
extern void _link_end();
extern void _setup_start();
extern void _setup_end();
extern void _map_start();
extern void _map_text();
extern void _map_data();
extern void _map_end();
extern void _kp_end();
#endif // __ASSEMBLY__

#endif // _KP_SETUP_H_