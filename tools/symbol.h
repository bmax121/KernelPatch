/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_SYBMOL_H_
#define _KP_TOOL_SYBMOL_H_

#include <stdint.h>
#include <stdbool.h>

#include "image.h"
#include "order.h"
#include "kallsym.h"
#include "preset.h"

int32_t get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol);
int32_t get_symbol_offset_exit(kallsym_t *info, char *img, char *symbol);
int32_t find_suffixed_symbol(kallsym_t *kallsym, char *img_buf, const char *symbol);
void select_map_area(kallsym_t *kallsym, char *image_buf, int32_t *map_start, int32_t *max_size);
int fillin_map_symbol(kallsym_t *kallsym, char *img_buf, map_symbol_t *symbol, int32_t target_is_be);
int fillin_patch_symbol(kallsym_t *kallsym, char *img_buf, int imglen, patch_symbol_t *symbol, int32_t target_is_be,
                        bool is_android);

#endif