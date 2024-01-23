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

#include "patch.h"
#include "kallsym.h"
#include "image.h"
#include "common.h"
#include "order.h"
#include "preset.h"
#include "symbol.h"

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

void print_kp_image_info(const char *kpimg_path)
{
    fprintf(stdout, "path=%s\n", kpimg_path);
    char *kpimg;
    int len = 0;
    read_file(kpimg_path, &kpimg, &len);
    preset_t *preset = (preset_t *)kpimg;

    setup_header_t *header = &preset->header;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags | CONFIG_ANDROID;
    bool is_debug = header->config_flags | CONFIG_DEBUG;

    fprintf(stdout, "version:%x\n", ver_num);
    fprintf(stdout, "compile_time:%s\n", header->compile_time);
    fprintf(stdout, "config=%s,%s\n", is_debug ? "debug" : "release", is_android ? "android" : "linux");
    fprintf(stdout, "\n");

    free(kpimg);
}

int parse_patched_img(patched_kimg_t *pimg)
{
    if (!pimg->kimg_path) tools_error_exit("empty kernel image\n");

    read_file(pimg->kimg_path, &pimg->kimg, &pimg->kimg_len);
    char *kimg = pimg->kimg;
    int kimg_len = pimg->kimg_len;

    // kernel image infomation
    kernel_info_t *kinfo = &pimg->kinfo;
    if (get_kernel_info(kinfo, kimg, kimg_len)) tools_error_exit("get_kernel_info error\n");

    // patched or new
    preset_t *old_preset = get_preset(kimg, kimg_len);
    pimg->preset = old_preset;
    if (old_preset) {
        tools_logi("patched image ...\n");
        int saved_kimg_len = old_preset->setup.kimg_size;
        int align_kimg_len = (char *)old_preset - kimg;
        if (align_kimg_len == (int)align_ceil(saved_kimg_len, SZ_4K)) {
            pimg->ori_kimg_len = saved_kimg_len;
        } else {
            pimg->ori_kimg_len = align_kimg_len;
        }
        memcpy(kimg, old_preset->setup.header_backup, sizeof(old_preset->setup.header_backup));
    } else {
        tools_logi("new image ...\n");
        pimg->ori_kimg_len = pimg->kimg_len;
    }

    free(kimg);
    return 0;
}

void print_patched_image_info(const char *kimg_path)
{
    fprintf(stdout, "path=%s\n", kimg_path);

    patched_kimg_t *pimg = (patched_kimg_t *)malloc(sizeof(patched_kimg_t));
    memset(pimg, 0, sizeof(*pimg));
    pimg->kimg_path = kimg_path;
    parse_patched_img(pimg);

    fprintf(stdout, "len=0x%x\n", pimg->kimg_len);
    preset_t *preset = pimg->preset;
    fprintf(stdout, "patched=%s\n", preset ? "true" : "false");

    if (preset) {
    }

    fprintf(stdout, "\n");
    free(pimg);
}

int patch_update_img(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey,
                     char **embed_kpm_path, int embed_kpm_num, char **detach_kpm_names, int detach_kpm_num)
{
    set_log_enable(true);

    if (!kpimg_path) tools_error_exit("empty kpimg\n");
    if (!out_path) tools_error_exit("empty out image path\n");
    if (!superkey) tools_error_exit("empty superkey\n");

    patched_kimg_t *pimg = (patched_kimg_t *)malloc(sizeof(patched_kimg_t));
    memset(pimg, 0, sizeof(*pimg));

    pimg->kimg_path = kimg_path;
    parse_patched_img(pimg);

    // kimg base info
    kernel_info_t *kinfo = &pimg->kinfo;
    int align_kernel_size = align_ceil(kinfo->kernel_size, SZ_4K);

    // kimg kallsym
    char *kallsym_kimg = (char *)malloc(pimg->ori_kimg_len);
    memcpy(kallsym_kimg, pimg->kimg, pimg->ori_kimg_len);
    kallsym_t kallsym = { 0 };
    if (analyze_kallsym_info(&kallsym, kallsym_kimg, pimg->ori_kimg_len, ARM64, 1)) {
        tools_error_exit("analyze_kallsym_info error\n");
    }

    // kpimg
    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file_align(kpimg_path, &kpimg, &kpimg_len, 0x10);

    // extra
    int extra_size = 0;

    // copy to out image
    int ori_kimg_len = pimg->ori_kimg_len;
    int align_kimg_len = align_ceil(pimg->kimg_len, SZ_4K);
    int out_img_len = align_kimg_len + kpimg_len;
    char *out_img = (char *)malloc(out_img_len);
    memcpy(out_img, pimg->kimg, ori_kimg_len);
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
    setup->extra_size = extra_size;

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
    fillin_patch_symbol(&kallsym, kallsym_kimg, &setup->patch_symbol, kinfo->is_be, 0);

    // superkey
    strncpy((char *)setup->superkey, superkey, SUPER_KEY_LEN - 1);
    tools_logi("superkey: %s\n", setup->superkey);

    // extra

    // modify kernel entry
    int paging_init_offset = get_symbol_offset_exit(&kallsym, kallsym_kimg, "paging_init");
    setup->paging_init_offset = relo_branch_func(kallsym_kimg, paging_init_offset);
    int text_offset = align_kimg_len + SZ_4K;
    b((uint32_t *)(out_img + kinfo->b_stext_insn_offset), kinfo->b_stext_insn_offset, text_offset);

    // write out
    write_file(out_path, out_img, out_img_len);

    // free
    free(kallsym_kimg);
    free(kpimg);
    free(out_img);

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

    write_file(out_path, kimg, kimg_size);
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

    write_file(out_path, kimg, kimg_len);

    free(origin_key);
    free(kimg);

    return 0;
}

int dump_kallsym(const char *kimg_path)
{
    if (!kimg_path) tools_error_exit("empty kernel image\n");

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
    free(kimg);
    return 0;
}