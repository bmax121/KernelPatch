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

#define EXTRA_ITEM_MAX_NUM 32

typedef struct
{
    // in
    const char *kimg_path;

    // out
    char *kimg;
    int kimg_len;
    int ori_kimg_len;
    kernel_info_t kinfo;
    preset_t *preset;
    int embed_item_num;
    const char *embed_item[EXTRA_ITEM_MAX_NUM];
} patched_kimg_t;

preset_t *get_preset(const char *kimg, int kimg_len);

uint32_t get_kpimg_version(const char *kpimg_path);
int patch_update_img(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey,
                     char **embed_kpm, char **embed_kpm_args, int embed_kpm_num, char **detach_kpm, int detach_kpm_num);
int unpatch_img(const char *kimg_path, const char *out_path);
int reset_key(const char *kimg_path, const char *out_path, const char *key);
int dump_kallsym(const char *kimg_path);

void print_kp_image_info(const char *kpimg_path);
void print_patched_image_info(const char *kimg_path);

#endif
