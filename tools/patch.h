/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_PATCH_H_
#define _KP_TOOL_PATCH_H_

#include <stdint.h>
#include <string.h>

#include "preset.h"
#include "image.h"

#define KPM_MAX_NUM 32

typedef struct
{
    //
    const char *kimg_path;
    const char *kimg;
    int kimg_len;
    kernel_info_t kinfo;
    const char *embed[KPM_MAX_NUM];
    preset_t *preset;

    //

} image_patch_t;

preset_t *get_preset(const char *kimg, int kimg_len);

uint32_t get_kpimg_version(const char *kpimg_path);
int patch_img(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey);
int unpatch_img(const char *kimg_path, const char *out_path);
int reset_key(const char *kimg_path, const char *out_path, const char *key);
int dump_kallsym(const char *kimg_path);

#endif
