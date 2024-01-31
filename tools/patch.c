/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>

#define _GNU_SOURCE
#define __USE_GNU

#include "patch.h"
#include "kallsym.h"
#include "image.h"
#include "common.h"
#include "order.h"
#include "preset.h"
#include "symbol.h"
#include "kpm.h"

preset_t *get_preset(const char *kimg, int kimg_len)
{
    char magic[MAGIC_LEN] = KP_MAGIC;
    return (preset_t *)memmem(kimg, kimg_len, magic, sizeof(magic));
}

uint32_t get_kpimg_version(const char *kpimg_path)
{
    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file(kpimg_path, &kpimg, &kpimg_len);
    preset_t *preset = get_preset(kpimg, kpimg_len);
    if (!preset) tools_error_exit("not patched kernel image\n");
    version_t ver = preset->header.kp_version;
    uint32_t version = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    return version;
}

void print_preset_info(preset_t *preset)
{
    setup_header_t *header = &preset->header;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = !!(header->config_flags & CONFIG_ANDROID);
    bool is_debug = !!(header->config_flags & CONFIG_DEBUG);

    fprintf(stdout, "version=0x%x\n", ver_num);
    fprintf(stdout, "compile_time=%s\n", header->compile_time);
    fprintf(stdout, "config=%s,%s\n", is_debug ? "debug" : "release", is_android ? "android" : "linux");
}

void print_kp_image_info_path(const char *kpimg_path)
{
    char *kpimg;
    int len = 0;
    read_file(kpimg_path, &kpimg, &len);
    preset_t *preset = (preset_t *)kpimg;
    fprintf(stdout, INFO_KP_IMG_SESSION "\n");
    print_preset_info(preset);
    fprintf(stdout, "\n");
    free(kpimg);
}

int parse_image_patch_info(const char *kimg, int kimg_len, patched_kimg_t *pimg)
{
    pimg->kimg = kimg;
    pimg->kimg_len = kimg_len;

    // kernel image infomation
    kernel_info_t *kinfo = &pimg->kinfo;
    if (get_kernel_info(kinfo, kimg, kimg_len)) tools_error_exit("get_kernel_info error\n");

    // find banner
    char linux_banner_prefix[] = "Linux version ";
    size_t prefix_len = strlen(linux_banner_prefix);
    const char *imgend = pimg->kimg + pimg->kimg_len;
    const char *banner = (char *)pimg->kimg;
    while ((banner = (char *)memmem(banner + 1, imgend - banner, linux_banner_prefix, prefix_len)) != NULL) {
        if (isdigit(*(banner + prefix_len)) && *(banner + prefix_len + 1) == '.') {
            pimg->banner = banner;
            break;
        }
    }
    if (!pimg->banner) tools_error_exit("can't find linux banner\n");

    // patched or new
    preset_t *old_preset = get_preset(kimg, kimg_len);
    pimg->preset = old_preset;

    if (!old_preset) {
        tools_logi("new kernel image ...\n");
        pimg->ori_kimg_len = pimg->kimg_len;
        return 0;
    }

    tools_logi("patched kernel image ...\n");
    int saved_kimg_len = old_preset->setup.kimg_size;
    int align_kimg_len = (char *)old_preset - kimg;
    if (align_kimg_len != (int)align_ceil(saved_kimg_len, SZ_4K)) tools_error_exit("saved kernel image size error\n");
    pimg->ori_kimg_len = saved_kimg_len;

    memcpy((char *)kimg, old_preset->setup.header_backup, sizeof(old_preset->setup.header_backup));

    // extra
    int extra_offset = align_kimg_len + old_preset->setup.kpimg_size;
    int extra_size = old_preset->setup.extra_size;

    const char *item_addr = kimg + extra_offset;

    while (item_addr < item_addr + extra_size) {
        patch_extra_item_t *item = (patch_extra_item_t *)item_addr;
        if (item->type == EXTRA_TYPE_NONE) break;
        pimg->embed_item[pimg->embed_item_num++] = item;
        item_addr += sizeof(patch_extra_item_t);
        item_addr += item->args_size;
        item_addr += item->con_size;
    }

    return 0;
}

int parse_image_patch_info_path(const char *kimg_path, patched_kimg_t *pimg)
{
    if (!kimg_path) tools_error_exit("empty kernel image\n");

    char *kimg;
    int kimg_len;
    read_file(kimg_path, &kimg, &kimg_len);
    int rc = parse_image_patch_info(kimg, kimg_len, pimg);
    free(kimg);
    return rc;
}

void print_image_patch_info(patched_kimg_t *pimg)
{
    preset_t *preset = pimg->preset;

    fprintf(stdout, INFO_KERNEL_IMG_SESSION "\n");
    fprintf(stdout, "banner=%s", pimg->banner);

    if (pimg->banner[strlen(pimg->banner) - 1] != '\n') fprintf(stdout, "\n");
    fprintf(stdout, "patched=%s\n", preset ? "true" : "false");

    if (preset) {
        fprintf(stdout, INFO_KP_IMG_SESSION "\n");
        print_preset_info(preset);
        fprintf(stdout, "extra_num=%d\n", pimg->embed_item_num);

        for (int i = 0; i < pimg->embed_item_num; i++) {
            patch_extra_item_t *item = pimg->embed_item[i];
            const char *type = "none";
            switch (item->type) {
            case EXTRA_TYPE_KPM:
                type = "kpm";
                break;
            case EXTRA_TYPE_SHELL:
                type = "shell";
                break;
            case EXTRA_TYPE_EXEC:
                type = "exec";
                break;
            case EXTRA_TYPE_RAW:
                type = "raw";
                break;
            }
            fprintf(stdout, INFO_EXTRA_SESSION "\n");
            fprintf(stdout, "index=%d\n", i);
            fprintf(stdout, "type=%s\n", type);
            fprintf(stdout, "con_size=0x%x\n", item->con_size);
            fprintf(stdout, "args_size=0x%x\n", item->args_size);
            if (item->type == EXTRA_TYPE_KPM) {
                kpm_info_t kpm_info = { 0 };
                void *kpm = (kpm_info_t *)((uintptr_t)item + sizeof(patch_extra_item_t) + item->args_size);
                int rc = get_kpm_info(kpm, item->con_size, &kpm_info);
                if (rc) tools_error_exit("get kpm infomation error: %d\n", rc);
                print_kpm_info(&kpm_info);
            }
        }
    }
}

void print_image_patch_info_path(const char *kimg_path)
{
    patched_kimg_t pimg = { 0 };
    char *kimg;
    int kimg_len;
    read_file(kimg_path, &kimg, &kimg_len);
    int rc = parse_image_patch_info(kimg, kimg_len, &pimg);
    print_image_patch_info(&pimg);
    free(kimg);
}

// todo: opt
int patch_update_img(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey,
                     char **embed_kpm_path, char **embed_kpm_args, int embed_kpm_num, char **detach_kpm_names,
                     int detach_kpm_num)
{
    set_log_enable(true);

    if (!kpimg_path) tools_error_exit("empty kpimg\n");
    if (!out_path) tools_error_exit("empty out image path\n");
    if (!superkey) tools_error_exit("empty superkey\n");

    patched_kimg_t pimg = { 0 };
    char *kimg;
    int kimg_len;
    read_file(kimg_path, &kimg, &kimg_len);
    int rc = parse_image_patch_info(kimg, kimg_len, &pimg);
    if (rc) tools_error_exit("parse kernel image error\n");
    // print_image_patch_info(&pimg);

    // kimg base info
    kernel_info_t *kinfo = &pimg.kinfo;
    int align_kernel_size = align_ceil(kinfo->kernel_size, SZ_4K);

    // kimg kallsym
    char *kallsym_kimg = (char *)malloc(pimg.ori_kimg_len);
    memcpy(kallsym_kimg, pimg.kimg, pimg.ori_kimg_len);
    kallsym_t kallsym = { 0 };
    if (analyze_kallsym_info(&kallsym, kallsym_kimg, pimg.ori_kimg_len, ARM64, 1)) {
        tools_error_exit("analyze_kallsym_info error\n");
    }

    // kpimg
    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file_align(kpimg_path, &kpimg, &kpimg_len, 0x10);

    // extra
    int extra_size = 0;
    int extra_num = 0;

    struct extra_items_wrap
    {
        patch_extra_item_t item;
        const char *name;
        extra_item_type type;
        const char *data;
        const char *args;
        int data_len;
        int args_len;
    } *extra_items = (struct extra_items_wrap *)malloc(sizeof(struct extra_items_wrap) * EXTRA_ITEM_MAX_NUM);

    memset(extra_items, 0, sizeof(struct extra_items_wrap) * EXTRA_ITEM_MAX_NUM);

    // new extra
    for (int i = 0; i < embed_kpm_num && extra_num < EXTRA_ITEM_MAX_NUM; i++) {
        char *kpm_data;
        int kpm_len = 0;
        int args_len = 0;
        read_file_align(embed_kpm_path[i], &kpm_data, &kpm_len, EXTRA_ALIGN);

        kpm_info_t kpm_info = { 0 };
        int rc = get_kpm_info(kpm_data, kpm_len, &kpm_info);
        if (rc) tools_error_exit("can get infomation of kpm, path: %s\n", embed_kpm_path[i]);

        struct extra_items_wrap *item_wrap = extra_items + extra_num;
        patch_extra_item_t *item = &item_wrap->item;

        // set wrap
        const char *args = embed_kpm_args[i];
        if (args) args_len = align_ceil(strlen(args), EXTRA_ALIGN);
        item_wrap->type = EXTRA_TYPE_KPM;
        item_wrap->data = kpm_data;
        item_wrap->data_len = kpm_len;
        item_wrap->args = args;
        item_wrap->args_len = args_len;
        item_wrap->name = kpm_info.name;

        // set runtime item
        strcpy(item->name, kpm_info.name);
        item->priority = 0;
        item->type = EXTRA_TYPE_KPM;
        item->con_size = kpm_len;
        item->args_size = args_len;
        if ((is_be() ^ kinfo->is_be)) {
            item->priority = i32swp(item->priority);
            item->type = i32swp(item->type);
            item->con_size = i32swp(item->con_size);
            item->args_size = i32swp(item->args_size);
        }

        extra_size += (kpm_len + args_len + sizeof(patch_extra_item_t));
        extra_num++;
    }

    // reserved pre-patched extra
    for (int i = 0; i < pimg.embed_item_num; i++) {
        struct extra_items_wrap *item_wrap = extra_items + extra_num;
        patch_extra_item_t *item = pimg.embed_item[i];

        item_wrap->type = item->type;
        if ((is_be() ^ kinfo->is_be)) item_wrap->type = i32swp(item_wrap->type);

        bool detach = false;

        if (item_wrap->type == EXTRA_TYPE_KPM) {
            kpm_info_t kpm_info = { 0 };
            void *kpm = (kpm_info_t *)((uintptr_t)item + sizeof(patch_extra_item_t) + item->args_size);
            get_kpm_info(kpm, item->con_size, &kpm_info);
            for (int j = 0; j < detach_kpm_num; j++) {
                if (!strcmp(detach_kpm_names[j], kpm_info.name)) {
                    detach = true;
                    break;
                }
            }
            if (!detach) {
                memcpy(&item_wrap->item, item, sizeof(*item));
                item_wrap->data = (const char *)kpm;
                item_wrap->args = (const char *)item + sizeof(*item);
                item_wrap->data_len = item->con_size;
                item_wrap->args_len = item->args_size;
                if ((is_be() ^ kinfo->is_be)) {
                    item_wrap->data_len = i32swp(item_wrap->data_len);
                    item_wrap->args_len = i32swp(item_wrap->args_len);
                }
                item_wrap->name = kpm_info.name;

                extra_size += sizeof(*item) + item_wrap->data_len + item_wrap->args_len;
                extra_num++;
                tools_logi("reserved embeded kpm: %s\n", kpm_info.name);
            } else {
                tools_logi("detact embeded kpm: %s\n", kpm_info.name);
            }
        } else {
            // todo
        }
    }

    extra_size += sizeof(patch_extra_item_t);

    // copy to out image
    int ori_kimg_len = pimg.ori_kimg_len;
    int align_kimg_len = align_ceil(ori_kimg_len, SZ_4K);
    int out_img_len = align_kimg_len + kpimg_len;
    tools_logi("layout kimg: 0x0-0x%x, kpimg: 0x%x-0x%x, extra: 0x%x-0x%x\n", ori_kimg_len, align_kimg_len, kpimg_len,
               align_kimg_len + kpimg_len, extra_size);

    char *out_img = (char *)malloc(out_img_len);
    memcpy(out_img, pimg.kimg, ori_kimg_len);
    memset(out_img + ori_kimg_len, 0, align_kimg_len - ori_kimg_len);
    memcpy(out_img + align_kimg_len, kpimg, kpimg_len);

    // set preset
    preset_t *preset = (preset_t *)(out_img + align_kimg_len);

    setup_header_t *header = &preset->header;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags | CONFIG_ANDROID;
    bool is_debug = header->config_flags | CONFIG_DEBUG;
    tools_logi("kpimg version: %x\n", ver_num);
    tools_logi("kpimg compile time: %s\n", header->compile_time);
    tools_logi("kpimg config: %s, %s\n", is_debug ? "debug" : "release", is_android ? "android" : "linux");

    setup_preset_t *setup = &preset->setup;
    memset(setup, 0, sizeof(preset->setup));

    setup->kernel_version.major = kallsym.version.major;
    setup->kernel_version.minor = kallsym.version.minor;
    setup->kernel_version.patch = kallsym.version.patch;
    setup->kimg_size = ori_kimg_len;
    setup->kpimg_size = kpimg_len;

    setup->kernel_size = kinfo->kernel_size;
    setup->page_shift = kinfo->page_shift;
    setup->setup_offset = align_kimg_len;
    setup->start_offset = align_kernel_size;
    setup->extra_size = extra_size; // ending with empty item

    int map_start, map_max_size;
    select_map_area(&kallsym, kallsym_kimg, &map_start, &map_max_size);
    setup->map_offset = map_start;
    setup->map_max_size = map_max_size;
    tools_logi("map_start: 0x%x, max_size: 0x%x\n", map_start, map_max_size);

    setup->kallsyms_lookup_name_offset = get_symbol_offset_exit(&kallsym, kallsym_kimg, "kallsyms_lookup_name");

    setup->printk_offset = get_symbol_offset_zero(&kallsym, kallsym_kimg, "printk");
    if (!setup->printk_offset) setup->printk_offset = get_symbol_offset_zero(&kallsym, kallsym_kimg, "_printk");
    if (!setup->printk_offset) tools_error_exit("no symbol printk\n");

    if ((is_be() ^ kinfo->is_be)) {
        setup->kimg_size = i64swp(setup->kimg_size);
        setup->kernel_size = i64swp(setup->kernel_size);
        setup->page_shift = i64swp(setup->page_shift);
        setup->setup_offset = i64swp(setup->setup_offset);
        setup->map_offset = i64swp(setup->map_offset);
        setup->map_max_size = i64swp(setup->map_max_size);
        setup->kallsyms_lookup_name_offset = i64swp(setup->kallsyms_lookup_name_offset);
        setup->paging_init_offset = i64swp(setup->paging_init_offset);
        setup->printk_offset = i64swp(setup->printk_offset);
    }

    // map symbol
    fillin_map_symbol(&kallsym, kallsym_kimg, &setup->map_symbol, kinfo->is_be);

    // header backup
    memcpy(setup->header_backup, kallsym_kimg, sizeof(setup->header_backup));

    // start symbol
    fillin_patch_symbol(&kallsym, kallsym_kimg, ori_kimg_len, &setup->patch_symbol, kinfo->is_be, 0);

    // superkey
    strncpy((char *)setup->superkey, superkey, SUPER_KEY_LEN - 1);
    tools_logi("superkey: %s\n", setup->superkey);

    // modify kernel entry
    int paging_init_offset = get_symbol_offset_exit(&kallsym, kallsym_kimg, "paging_init");
    setup->paging_init_offset = relo_branch_func(kallsym_kimg, paging_init_offset);
    int text_offset = align_kimg_len + SZ_4K;
    b((uint32_t *)(out_img + kinfo->b_stext_insn_offset), kinfo->b_stext_insn_offset, text_offset);

    // write out
    write_file(out_path, out_img, out_img_len, false);

    // write extra
    for (int i = 0; i < extra_num; i++) {
        struct extra_items_wrap *item_wrap = &extra_items[i];
        const char *type = EXTRA_TYPE_NONE;
        switch (item_wrap->type) {
        case EXTRA_TYPE_KPM:
            type = "kpm";
            break;
        case EXTRA_TYPE_SHELL:
            type = "shell";
            break;
        default:
            break;
        }

        patch_extra_item_t *item = &item_wrap->item;
        tools_logi("embedding %s, name: %s, size: 0x%x + 0x%x + 0x%x\n", type, item_wrap->name, (int)sizeof(*item),
                   item_wrap->args_len, item_wrap->data_len);

        write_file(out_path, (void *)item, sizeof(*item), true);
        if (item_wrap->args_len > 0) write_file(out_path, (void *)item_wrap->args, item_wrap->args_len, true);
        write_file(out_path, (void *)item_wrap->data, item_wrap->data_len, true);
    }

    // guard extra
    patch_extra_item_t empty_item = {
        .type = EXTRA_TYPE_NONE,
        .priority = 0,
        .con_size = 0,
    };
    write_file(out_path, (void *)&empty_item, sizeof(empty_item), true);

    // free
    free(extra_items);
    free(kallsym_kimg);
    free(kpimg);
    free(out_img);
    free(kimg);

    tools_logi("patch done: %s\n", out_path);

    set_log_enable(false);
    return 0;
}

int unpatch_img(const char *kimg_path, const char *out_path)
{
    if (!kimg_path) tools_error_exit("empty kernel image\n");
    if (!out_path) tools_error_exit("empty out image path\n");

    char *kimg = NULL;
    int kimg_len = 0;
    read_file(kimg_path, &kimg, &kimg_len);

    preset_t *preset = get_preset(kimg, kimg_len);
    if (!preset) tools_error_exit("not patched kernel image\n");

    memcpy(kimg, preset->setup.header_backup, sizeof(preset->setup.header_backup));
    int kimg_size = preset->setup.kimg_size ?: ((char *)preset - kimg);

    write_file(out_path, kimg, kimg_size, false);
    free(kimg);
    return 0;
}

int reset_key(const char *kimg_path, const char *out_path, const char *superkey)
{
    if (!kimg_path) tools_error_exit("empty kernel image\n");
    if (!out_path) tools_error_exit("empty out image path\n");
    if (!superkey) tools_error_exit("empty superkey\n");

    if (strlen(superkey) <= 0) tools_error_exit("empty superkey\n");
    if (strlen(superkey) >= SUPER_KEY_LEN) tools_error_exit("too long superkey\n");

    char *kimg = NULL;
    int kimg_len = 0;
    read_file(kimg_path, &kimg, &kimg_len);

    preset_t *preset = get_preset(kimg, kimg_len);
    if (!preset) tools_error_exit("not patched kernel image\n");

    char *origin_key = strdup((char *)preset->setup.superkey);
    strcpy((char *)preset->setup.superkey, superkey);
    tools_logi("reset superkey: %s -> %s\n", origin_key, preset->setup.superkey);

    write_file(out_path, kimg, kimg_len, false);

    free(origin_key);
    free(kimg);

    return 0;
}

int dump_kallsym(const char *kimg_path)
{
    if (!kimg_path) tools_error_exit("empty kernel image\n");
    set_log_enable(true);
    // read image files
    char *kimg = NULL;
    int kimg_len = 0;
    read_file(kimg_path, &kimg, &kimg_len);

    kallsym_t kallsym;
    if (analyze_kallsym_info(&kallsym, kimg, kimg_len, ARM64, 1)) {
        fprintf(stdout, "analyze_kallsym_info error\n");
        return -1;
    }
    dump_all_symbols(&kallsym, kimg);
    set_log_enable(false);
    free(kimg);
    return 0;
}