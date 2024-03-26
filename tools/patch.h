/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_PATCH_H_
#define _KP_TOOL_PATCH_H_

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "preset.h"
#include "image.h"

#define INFO_KERNEL_IMG_SESSION "[kernel]"
#define INFO_KP_IMG_SESSION "[kpimg]"
#define INFO_ADDITIONAL_SESSION "[additional]"
#define INFO_EXTRA_SESSION "[extras]"
#define INFO_EXTRA_SESSION_N "[extra %d]"

#define EXTRA_ITEM_MAX_NUM 32

typedef struct
{
    const char *kimg;
    int32_t kimg_len;
    int32_t ori_kimg_len;
    const char *banner;
    kernel_info_t kinfo;
    preset_t *preset;
    int32_t embed_item_num;
    patch_extra_item_t *embed_item[EXTRA_ITEM_MAX_NUM];
} patched_kimg_t;

typedef struct
{
    int32_t extra_type;
    bool is_path;
    union
    {
        const char *path;
        const char *name;
    };
    const char *set_args;
    const char *set_name;
    const char *set_event;
    int32_t priority;
    const char *data;
    patch_extra_item_t *item;
} extra_config_t;

typedef struct
{
    char *kfile, *kimg;
    int32_t kfile_len, kimg_len;
    bool is_uncompressed_img;
} kernel_file_t;

void read_kernel_file(const char *path, kernel_file_t *kernel_file);
void new_kernel_file(kernel_file_t *kernel_file, kernel_file_t *old, int32_t kimg_len, bool is_different_endian);
void update_kernel_file_img_len(kernel_file_t *kernel_file, int32_t kimg_len, bool is_different_endian);
void write_kernel_file(kernel_file_t *kernel_file, const char *path);
void free_kernel_file(kernel_file_t *kernel_file);

preset_t *get_preset(const char *kimg, int kimg_len);

uint32_t get_kpimg_version(const char *kpimg_path);
int extra_str_type(const char *extra_str);
const char *extra_type_str(extra_item_type extra_type);
int patch_update_img(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey,
                     bool root_skey, const char **additional, const char *kpatch_path, extra_config_t *extra_configs,
                     int extra_config_num);
int unpatch_img(const char *kimg_path, const char *out_path);
int reset_key(const char *kimg_path, const char *out_path, const char *key);
int dump_kallsym(const char *kimg_path);

int print_kp_image_info_path(const char *kpimg_path);
int print_image_patch_info(patched_kimg_t *pimg);
int print_image_patch_info_path(const char *kimg_path);

#endif
