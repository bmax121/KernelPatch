/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_COMMON_H_
#define _KP_COMMON_H_

#include <stdint.h>
#include <stdbool.h>

#define VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))

typedef enum
{
    little = 0,
    big = 1
} endian_t;

extern uint32_t kver;
extern uint32_t kpver;
extern endian_t endian;

extern const char kernel_patch_logo[];

extern void _kp_start();
extern void _kp_text_start();
extern void _kp_text_end();
extern void _kp_data_start();
extern void _kp_data_end();
extern void _kp_end();

extern uint64_t _kp_hook_start;
extern uint64_t _kp_hook_end;

extern uint64_t _kp_extra_start;
extern uint64_t _kp_extra_end;

extern uint64_t _kp_rox_start;
extern uint64_t _kp_rox_end;
extern uint64_t _kp_rw_start;
extern uint64_t _kp_rw_end;

extern uint64_t _kp_region_start;
extern uint64_t _kp_region_end;

static inline bool is_kp_text_area(unsigned long addr)
{
    return addr >= (unsigned long)_kp_text_start && addr < (unsigned long)_kp_text_end;
}

static inline bool is_kp_hook_area(unsigned long addr)
{
    return addr >= (unsigned long)_kp_hook_start && addr < (unsigned long)_kp_hook_end;
}

static inline bool is_kpm_rox_area(unsigned long addr)
{
    return addr >= (unsigned long)_kp_rox_start && addr < (unsigned long)_kp_rox_end;
}

#endif