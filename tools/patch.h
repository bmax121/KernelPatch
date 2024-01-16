/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <stdint.h>
#include <string.h>

#include "preset.h"

preset_t *get_preset(const char *kimg, int kimg_len);
int patch_img(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey);
int unpatch_img(const char *kimg_path, const char *out_path);
int reset_key(const char *k_img_path, const char *key, const char *out_path);
int dump_kallsym(const char *k_img_path);
