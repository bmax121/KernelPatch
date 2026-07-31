/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#define _GNU_SOURCE
#define __USE_GNU

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>

#include "kallsym.h"
#include "bootimg.h"
#include "patch.h"
#include "kallsym.h"
#include "image.h"
#include "common.h"
#include "order.h"
#include "preset.h"
#include "symbol.h"
#include "kpm.h"
#include "x86_64.h"
#include "lib/sha/sha256.h"

void read_kernel_file(const char *path, kernel_file_t *kernel_file)
{
    int img_offset = 0;
    read_file(path, &kernel_file->kfile, &kernel_file->kfile_len);
    kernel_file->is_uncompressed_img = kernel_file->kfile_len >= 20 &&
                                       !strncmp("UNCOMPRESSED_IMG", kernel_file->kfile, 16);
    if (kernel_file->is_uncompressed_img) img_offset = 20;
    kernel_file->kimg = kernel_file->kfile + img_offset;
    kernel_file->kimg_len = kernel_file->kfile_len - img_offset;
}

void update_kernel_file_img_len(kernel_file_t *kernel_file, int kimg_len, bool is_different_endian)
{
    kernel_file->kimg_len = kimg_len;
    if (kernel_file->is_uncompressed_img) {
        *(uint32_t *)(kernel_file->kfile + 16) = (uint32_t)(is_different_endian ? i32swp(kimg_len) : kimg_len);
        kernel_file->kfile_len = kimg_len + 20;
    } else {
        kernel_file->kfile_len = kimg_len;
    }
}

void new_kernel_file(kernel_file_t *kernel_file, kernel_file_t *old, int kimg_len, bool is_different_endian)
{
    int prefix_len = old->kimg - old->kfile;
    int new_len = kimg_len + prefix_len;
    kernel_file->kfile = (char *)malloc(new_len);
    kernel_file->kimg = kernel_file->kfile + prefix_len;
    memcpy(kernel_file->kfile, old->kfile, prefix_len);
    kernel_file->is_uncompressed_img = old->is_uncompressed_img;
    update_kernel_file_img_len(kernel_file, kimg_len, is_different_endian);
}

void write_kernel_file(kernel_file_t *kernel_file, const char *path)
{
    write_file(path, kernel_file->kfile, kernel_file->kfile_len, false);
}

void free_kernel_file(kernel_file_t *kernel_file)
{
    free(kernel_file->kfile);
    kernel_file->kfile = NULL;
    kernel_file->kimg = NULL;
}

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
    if (!preset) tools_loge_exit("not patched kernel image\n");
    version_t ver = preset->header.kp_version;
    uint32_t version = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    return version;
}

int extra_str_type(const char *extra_str)
{
    int extra_type = EXTRA_TYPE_NONE;
    if (!strcmp(extra_str, EXTRA_TYPE_KPM_STR)) {
        extra_type = EXTRA_TYPE_KPM;
    } else if (!strcmp(extra_str, EXTRA_TYPE_EXEC_STR)) {
        extra_type = EXTRA_TYPE_EXEC;
    } else if (!strcmp(extra_str, EXTRA_TYPE_SHELL_STR)) {
        extra_type = EXTRA_TYPE_SHELL;
    } else if (!strcmp(extra_str, EXTRA_TYPE_RAW_STR)) {
        extra_type = EXTRA_TYPE_RAW;
    } else if (!strcmp(extra_str, EXTRA_TYPE_ANDROID_RC_STR)) {
        extra_type = EXTRA_TYPE_ANDROID_RC;
    } else {
    }
    return extra_type;
}

const char *extra_type_str(extra_item_type extra_type)
{
    switch (extra_type) {
    case EXTRA_TYPE_KPM:
        return EXTRA_TYPE_KPM_STR;
    case EXTRA_TYPE_EXEC:
        return EXTRA_TYPE_EXEC_STR;
    case EXTRA_TYPE_SHELL:
        return EXTRA_TYPE_SHELL_STR;
    case EXTRA_TYPE_RAW:
        return EXTRA_TYPE_RAW_STR;
    case EXTRA_TYPE_ANDROID_RC:
        return EXTRA_TYPE_ANDROID_RC_STR;
    case EXTRA_TYPE_KCONFIG_LEGACY:
        return EXTRA_TYPE_KCONFIG_LEGACY_STR;
    default:
        return EXTRA_TYPE_NONE_STR;
    }
}

static bool header_backup_has_valid_primary_entry(const uint8_t *header_backup)
{
    uint32_t primary_entry = u32le(*(const uint32_t *)header_backup);
    if ((primary_entry & 0xFC000000) == 0x14000000) return true;

    if (!memcmp(header_backup, "MZ", 2)) {
        primary_entry = u32le(*(const uint32_t *)(header_backup + 4));
        if ((primary_entry & 0xFC000000) == 0x14000000) return true;
    }

    return false;
}

static uint32_t preset_version_num(const preset_t *preset)
{
    version_t ver = preset->header.kp_version;
    return (ver.major << 16) + (ver.minor << 8) + ver.patch;
}

static void push_header_backup_candidate(size_t *candidates, int *candidate_num, size_t candidate)
{
    for (int i = 0; i < *candidate_num; i++) {
        if (candidates[i] == candidate) return;
    }
    candidates[(*candidate_num)++] = candidate;
}

static const uint8_t *preset_header_backup(const preset_t *preset)
{
    const uint8_t *setup = (const uint8_t *)&preset->setup;
    size_t candidates[4];
    int candidate_num = 0;
    size_t current_header_backup_offset = offsetof(setup_preset_t, header_backup);

    uint32_t ver_num = preset_version_num(preset);
    if (ver_num <= VERSION(0, 13, 1)) {
        push_header_backup_candidate(candidates, &candidate_num, current_header_backup_offset - 16);
        push_header_backup_candidate(candidates, &candidate_num, current_header_backup_offset);
    } else {
        push_header_backup_candidate(candidates, &candidate_num, current_header_backup_offset);
        push_header_backup_candidate(candidates, &candidate_num, current_header_backup_offset - 16);
    }

    push_header_backup_candidate(candidates, &candidate_num, current_header_backup_offset - 8);

    for (int i = 0; i < candidate_num; i++) {
        const uint8_t *header_backup = setup + candidates[i];
        if (header_backup_has_valid_primary_entry(header_backup)) return header_backup;
    }

    return setup + candidates[0];
}

static preset_t *find_patched_preset(const char *kimg, int kimg_len, int32_t *saved_kimg_len, int *align_kimg_len)
{
    const char *search_ptr = kimg;
    int search_len = kimg_len;

    while (search_len > 0) {
        preset_t *candidate = get_preset(search_ptr, search_len);
        if (!candidate) break;

        int32_t candidate_saved_kimg_len = (int32_t)u64le(candidate->setup.kimg_size);
        int candidate_align_kimg_len = (int)((const char *)candidate - kimg);
        const uint8_t *header_backup = preset_header_backup(candidate);

        if (candidate_align_kimg_len == (int)align_ceil(candidate_saved_kimg_len, SZ_4K) &&
            header_backup_has_valid_primary_entry(header_backup)) {
            if (saved_kimg_len) *saved_kimg_len = candidate_saved_kimg_len;
            if (align_kimg_len) *align_kimg_len = candidate_align_kimg_len;
            return candidate;
        }

        tools_logw("found magic string at 0x%x but saved kernel image size/header backup mismatch, ignoring\n",
                   candidate_align_kimg_len);

        search_ptr = (const char *)candidate + 1;
        search_len = kimg_len - (int)(search_ptr - kimg);
    }

    return NULL;
}

static uint32_t extra_item_header_version(const patch_extra_item_t *item)
{
    return PATCH_EXTRA_FLAGS_GET_HEADER_VERSION(item->flags);
}

static void sanitize_legacy_extra_item(patch_extra_item_t *item)
{
    if (extra_item_header_version(item) == PATCH_EXTRA_HEADER_VERSION_LEGACY && item->flags) {
        tools_logw("legacy extra item %s has dirty flags 0x%x, clearing for compatibility\n", item->name,
                   (uint32_t)item->flags);
        item->flags = 0;
    }
}

static bool is_legacy_kconfig_extra(const patch_extra_item_t *item)
{
    return extra_item_header_version(item) == PATCH_EXTRA_HEADER_VERSION_LEGACY &&
           item->type == EXTRA_TYPE_KCONFIG_LEGACY && !strcmp(item->name, EXTRA_TYPE_KCONFIG_LEGACY_STR);
}

static char *bytes_to_hexstr(const unsigned char *data, int len)
{
    char *buf = (char *)malloc(2 * len + 1);
    buf[2 * len] = '\0';
    for (int i = 0; i < len; i++) {
        sprintf(&buf[2 * i], "%02x", data[i]);
    }
    return buf;
}

void print_preset_info(preset_t *preset)
{
    setup_header_t *header = &preset->header;
    setup_preset_t *setup = &preset->setup;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags & CONFIG_ANDROID;
    bool is_debug = header->config_flags & CONFIG_DEBUG;
    bool is_x86_64 = header->config_flags & CONFIG_FLAG_X86_64;

    fprintf(stdout, INFO_KP_IMG_SESSION "\n");
    fprintf(stdout, "version=0x%x\n", ver_num);
    fprintf(stdout, "compile_time=%s\n", header->compile_time);
    fprintf(stdout, "config=%s,%s\n", is_android ? "android" : "linux", is_debug ? "debug" : "release");
    fprintf(stdout, "arch=%s\n", is_x86_64 ? "x86_64" : "arm64");
    fprintf(stdout, "superkey=%s\n", setup->superkey);

    // todo: remove compat version
    if (ver_num > 0xa04) {
        char *hexstr = bytes_to_hexstr(setup->root_superkey, ROOT_SUPER_KEY_HASH_LEN);
        fprintf(stdout, "root_superkey=%s\n", hexstr);
        free(hexstr);
    }

    fprintf(stdout, INFO_ADDITIONAL_SESSION "\n");
    char *addition = setup->additional;
    // todo: remove compat version
    if (ver_num <= 0xa04) {
        addition -= (ROOT_SUPER_KEY_HASH_LEN + SETUP_PRESERVE_LEN);
    }
    char *pos = addition;
    while (pos < addition + ADDITIONAL_LEN) {
        int len = *pos;
        if (!len) break;
        pos++;
        char backup = *(pos + len);
        *(pos + len) = 0;
        fprintf(stdout, "%s\n", pos);
        *(pos + len) = backup;
        pos += len;
    }
}

int print_kp_image_info_path(const char *kpimg_path)
{
    int rc = 0;
    char *kpimg;
    int len = 0;
    read_file(kpimg_path, &kpimg, &len);
    preset_t *preset = (preset_t *)kpimg;
    if (get_preset(kpimg, len) != preset) {
        rc = -ENOENT;
    } else {
        print_preset_info(preset);
        fprintf(stdout, "\n");
        free(kpimg);
    }
    return rc;
}

int parse_image_patch_info(const char *kimg, int kimg_len, patched_kimg_t *pimg)
{
    pimg->kimg = kimg;
    pimg->kimg_len = kimg_len;

    preset_t *old_preset = NULL;
    int32_t saved_kimg_len = 0;
    int align_kimg_len = 0;

    old_preset = find_patched_preset(kimg, kimg_len, &saved_kimg_len, &align_kimg_len);
    if (old_preset) {
        tools_logi("restore header backup before parsing patched kernel image\n");
        memcpy((char *)kimg, preset_header_backup(old_preset), HDR_BACKUP_SIZE);
    }

    // kernel image infomation
    kernel_info_t *kinfo = &pimg->kinfo;
    if (get_kernel_info(kinfo, kimg, kimg_len)) tools_loge_exit("get_kernel_info error\n");

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
    if (!pimg->banner) tools_loge_exit("can't find linux banner\n");

    if (!old_preset) {
        old_preset = find_patched_preset(kimg, kimg_len, &saved_kimg_len, &align_kimg_len);
        if (old_preset && (is_be() ^ kinfo->is_be)) {
            saved_kimg_len = i32swp(saved_kimg_len);
        }
    }

    pimg->preset = old_preset;

    if (!old_preset) {
        tools_logi("new kernel image ...\n");
        pimg->ori_kimg_len = pimg->kimg_len;
        return 0;
    }

    tools_logi("patched kernel image ...\n");
    pimg->ori_kimg_len = saved_kimg_len;

    memcpy((char *)kimg, preset_header_backup(old_preset), HDR_BACKUP_SIZE);

    // extra
    int extra_offset = align_kimg_len + old_preset->setup.kpimg_size;
    if (extra_offset > kimg_len) tools_loge_exit("kpimg length mismatch\n");
    if (extra_offset == kimg_len) return 0;

    int32_t extra_size = old_preset->setup.extra_size;
    if (is_be() ^ kinfo->is_be) extra_size = i32swp(extra_size);
    const char *item_pos = kimg + extra_offset;

    while (item_pos < kimg + extra_offset + extra_size) {
        patch_extra_item_t *item = (patch_extra_item_t *)item_pos;
        if (strcmp(EXTRA_HDR_MAGIC, item->magic)) break;
        if (item->type == EXTRA_TYPE_NONE) break;
        sanitize_legacy_extra_item(item);
        if (is_legacy_kconfig_extra(item)) {
            tools_logw("skip legacy embedded kconfig extra item during upgrade compatibility scan\n");
            item_pos += sizeof(patch_extra_item_t);
            item_pos += item->args_size;
            item_pos += item->con_size;
            continue;
        }
        if (pimg->embed_item_num >= EXTRA_ITEM_MAX_NUM) tools_loge_exit("too many embedded extra items\n");
        pimg->embed_item[pimg->embed_item_num++] = item;
        item_pos += sizeof(patch_extra_item_t);
        item_pos += item->args_size;
        item_pos += item->con_size;
    }

    return 0;
}

int parse_image_patch_info_path(const char *kimg_path, patched_kimg_t *pimg)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    int rc = parse_image_patch_info(kernel_file.kimg, kernel_file.kimg_len, pimg);
    free_kernel_file(&kernel_file);
    return rc;
}

int print_image_patch_info(patched_kimg_t *pimg)
{
    int rc = 0;

    preset_t *preset = pimg->preset;

    fprintf(stdout, INFO_KERNEL_IMG_SESSION "\n");
    fprintf(stdout, "banner=%s", pimg->banner);

    if (pimg->banner[strlen(pimg->banner) - 1] != '\n') fprintf(stdout, "\n");
    fprintf(stdout, "patched=%s\n", preset ? "true" : "false");

    if (preset) {
        print_preset_info(preset);

        fprintf(stdout, INFO_EXTRA_SESSION "\n");
        fprintf(stdout, "num=%d\n", pimg->embed_item_num);

        for (int i = 0; i < pimg->embed_item_num; i++) {
            patch_extra_item_t *item = pimg->embed_item[i];
            const char *type = extra_type_str(item->type);
            fprintf(stdout, INFO_EXTRA_SESSION_N "\n", i);
            fprintf(stdout, "index=%d\n", i);
            fprintf(stdout, "type=%s\n", type);
            fprintf(stdout, "name=%s\n", item->name);
            fprintf(stdout, "event=%s\n", item->event);
            fprintf(stdout, "priority=%d\n", item->priority);
            fprintf(stdout, "args_size=0x%x\n", item->args_size);
            fprintf(stdout, "args=%s\n", item->args_size > 0 ? (char *)item + sizeof(*item) : "");
            fprintf(stdout, "con_size=0x%x\n", item->con_size);
            fprintf(stdout, "flags=0x%x\n", item->flags);

            if (item->type == EXTRA_TYPE_KPM) {
                kpm_info_t kpm_info = { 0 };
                void *kpm = (kpm_info_t *)((uintptr_t)item + sizeof(patch_extra_item_t) + item->args_size);
                rc = get_kpm_info(kpm, item->con_size, &kpm_info);
                if (rc) tools_loge_exit("get kpm infomation error: %d\n", rc);
                fprintf(stdout, "version=%s\n", kpm_info.version);
                fprintf(stdout, "license=%s\n", kpm_info.license);
                fprintf(stdout, "author=%s\n", kpm_info.author);
                fprintf(stdout, "description=%s\n", kpm_info.description);
            }
        }
    }
    return rc;
}

int print_image_patch_info_path(const char *kimg_path)
{
    patched_kimg_t pimg = { 0 };
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    int rc = parse_image_patch_info(kernel_file.kimg, kernel_file.kimg_len, &pimg);
    print_image_patch_info(&pimg);
    free_kernel_file(&kernel_file);
    return rc;
}

static int extra_compare(const void *a, const void *b)
{
    extra_config_t *pa = (extra_config_t *)a;
    extra_config_t *pb = (extra_config_t *)b;
    return -(pa->priority - pb->priority);
}

static void extra_append(char *kimg, const void *data, int len, int *offset)
{
    memcpy(kimg + *offset, data, len);
    *offset += len;
}

static void hexstr_to_bytes(const char *hexstr, size_t out_len, unsigned char *out)
{
    for (size_t i = 0; i < out_len; i++) {
        char tmp[3] = { hexstr[i * 2], hexstr[i * 2 + 1], 0 };
        out[i] = (unsigned char)strtoul(tmp, NULL, 16);
    }
}

int hex_patch(char *img, size_t imglen,
                      const char *pattern_hex,
                      const char *replace_hex)
{
    size_t patternlen = strlen(pattern_hex) / 2;
    size_t replacelen = strlen(replace_hex) / 2;


    unsigned char pattern[32];
    unsigned char replace[32];

    hexstr_to_bytes(pattern_hex, patternlen, pattern);
    hexstr_to_bytes(replace_hex, replacelen, replace);

    unsigned char *p = memmem(img, imglen, pattern, patternlen);
    if (p) {
        memcpy(p, replace, replacelen);
    }else{
        return -1;
    }
    return 0;
}

static int disable_pi_map(char *img, size_t imglen)
{
    return hex_patch(
        img,
        imglen,
        "E60316AAE7031F2A3411889A",
        "E60316AAE7031F2AF40309AA"
    );
}

static int patch_update_x86(const char *kimg_path, const char *kpimg_path, const char *out_path,
                            const char *superkey, bool root_key, const char **additional,
                            int extra_config_num)
{
    if (extra_config_num) {
        tools_loge("x86 kpimg extras are not supported yet\n");
        return -1;
    }
    if (additional && additional[0]) {
        tools_loge("x86 kpimg additional properties are not supported yet\n");
        return -1;
    }

    x86_bzimage_t image;
    if (load_x86_bzimage(kimg_path, &image)) {
        tools_loge("load x86 bzImage failed\n");
        return -1;
    }

    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file(kpimg_path, &kpimg, &kpimg_len);
    if (kpimg_len < (int)sizeof(preset_t)) {
        tools_loge("x86 kpimg is too small\n");
        free(kpimg);
        free_x86_bzimage(&image);
        return -1;
    }

    preset_t *preset = (preset_t *)kpimg;
    char magic[MAGIC_LEN] = KP_MAGIC;
    if (memcmp(preset->header.magic, magic, MAGIC_LEN) ||
        !(preset->header.config_flags & CONFIG_FLAG_X86_64)) {
        tools_loge("kpimg is not an x86_64 payload\n");
        free(kpimg);
        free_x86_bzimage(&image);
        return -1;
    }

    setup_preset_t *setup = &preset->setup;
    memset(setup, 0, sizeof(*setup));
    kallsym_t kallsym = { 0 };
    int kver = 0;
    if (!find_linux_banner(&kallsym, image.flat, image.flat_size, &kver)) {
        setup->kernel_version.major = kallsym.version.major;
        setup->kernel_version.minor = kallsym.version.minor;
        setup->kernel_version.patch = kallsym.version.patch;
    }

    if (!root_key) {
        strncpy((char *)setup->superkey, superkey, SUPER_KEY_LEN - 1);
    } else if (superkey && superkey[0]) {
        BYTE digest[SHA256_BLOCK_SIZE];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const BYTE *)superkey, strnlen(superkey, SUPER_KEY_LEN));
        sha256_final(&ctx, digest);
        memcpy(setup->root_superkey, digest, ROOT_SUPER_KEY_HASH_LEN);
    }

    int rc = inject_x86_kpimg(&image, kpimg, kpimg_len);
    if (!rc) rc = write_x86_bzimage(&image, out_path);
    if (!rc) tools_logi("x86 patch done: %s\n", out_path);

    free(kpimg);
    free_x86_bzimage(&image);
    return rc;
}

int patch_update_img(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey,
                     bool root_key, const char **additional, extra_config_t *extra_configs, int extra_config_num)
{
    set_log_enable(true);

    if (!kpimg_path) tools_loge_exit("empty kpimg\n");
    if (!out_path) tools_loge_exit("empty out image path\n");
    if (!superkey && !root_key) tools_loge_exit("empty superkey\n");

    char *probe = NULL;
    int probe_len = 0;
    read_file(kimg_path, &probe, &probe_len);
    bool x86_bzimage = is_x86_bzimage(probe, probe_len);
    free(probe);
    if (x86_bzimage) {
        int rc = patch_update_x86(kimg_path, kpimg_path, out_path, superkey, root_key, additional,
                                  extra_config_num);
        set_log_enable(false);
        return rc;
    }

    patched_kimg_t pimg = { 0 };
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    if (kernel_file.is_uncompressed_img) tools_logw("kernel image with UNCOMPRESSED_IMG header\n");

    int rc = parse_image_patch_info(kernel_file.kimg, kernel_file.kimg_len, &pimg);
    if (rc) tools_loge_exit("parse kernel image error\n");
    // print_image_patch_info(&pimg);

    // kimg base info
    kernel_info_t *kinfo = &pimg.kinfo;
    int align_kernel_size = align_ceil(kinfo->kernel_size, SZ_4K);

    // kimg kallsym
    char *kallsym_kimg = (char *)malloc(pimg.ori_kimg_len);
    memcpy(kallsym_kimg, pimg.kimg, pimg.ori_kimg_len);
    kallsym_t kallsym = { 0 };
    int kver = 0;
    find_linux_banner(&kallsym, kallsym_kimg, pimg.ori_kimg_len, &kver);
    bool is_gki = kver >= 330240;  // 5.10
    tools_logi("is_gki: %s\n", is_gki ? "true" : "false");
    if (kver > 395008) {
        if(disable_pi_map(kernel_file.kimg, kernel_file.kimg_len))   //395008= (6<<16)+(7<<8)
        {
            tools_logi("kernel have patched or not found\n");
        }else{
            tools_logi("disabled PI_MAP for kernel version > 6.12.23\n");
        }
        
        
    }
    
    if (analyze_kallsym_info(&kallsym, kallsym_kimg, pimg.ori_kimg_len, ARM64, 1)) {
        tools_loge_exit("analyze_kallsym_info error\n");
    }

    // locate the kernel's own IKCONFIG gzip blob; runtime puff-inflates it
    size_t kcfg_start = 0, kcfg_bytes = 0;
    int kcfg_rc = find_ikconfig_blob(kallsym_kimg, pimg.ori_kimg_len, &kcfg_start, &kcfg_bytes);
    if (kcfg_rc) {
        tools_logw("kernel IKCONFIG blob not found (rc=%d), kconfig unavailable at runtime\n", kcfg_rc);
    } else {
        tools_logi("ikconfig gzip blob at 0x%zx, size 0x%zx (runtime puff)\n", kcfg_start, kcfg_bytes);
    }

    // kpimg
    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file_align(kpimg_path, &kpimg, &kpimg_len, 0x10);

    // extra
    int extra_size = 0;
    int extra_num = 0;

    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        if (config->is_path && config->extra_type == EXTRA_TYPE_NONE) {
            tools_loge_exit("extra type none\n");
        }
        if (config->set_event && strnlen(config->set_event, EXTRA_EVENT_LEN) >= EXTRA_EVENT_LEN) {
            tools_loge_exit("extra event too long: %s\n", config->set_event);
        }
        if (config->set_name && strnlen(config->set_name, EXTRA_NAME_LEN) >= EXTRA_NAME_LEN) {
            tools_loge_exit("extra name too long: %s\n", config->set_event);
        }

        patch_extra_item_t *item = NULL;
        if (config->item && config->data) {
            item = config->item;
        } else if (config->is_path) {
            // todo: free
            item = (patch_extra_item_t *)malloc(sizeof(patch_extra_item_t));
            memset(item, 0, sizeof(patch_extra_item_t));
            const char *path = config->path;
            char *data;
            int len = 0;
            read_file_align(path, &data, &len, EXTRA_ALIGN);
            config->data = data;
            item->con_size = len;
            // if name not set
            if (!config->set_name) {
                if (config->extra_type == EXTRA_TYPE_KPM) {
                    kpm_info_t kpm_info = { 0 };
                    int rc = get_kpm_info(data, len, &kpm_info);
                    if (rc) tools_loge_exit("can get infomation of kpm, path: %s\n", path);
                    strcpy(item->name, kpm_info.name);
                } else {
                    char *rsp = strrchr(path, '/');
                    strncpy(item->name, rsp ? rsp + 1 : path, EXTRA_NAME_LEN - 1);
                }
            }
        } else {
            const char *name = config->name;
            for (int j = 0; j < pimg.embed_item_num; j++) {
                item = pimg.embed_item[j];
                if (strcmp(name, item->name)) continue;
                if (is_be() ^ kinfo->is_be) {
                    item->type = i32swp(item->type);
                    item->priority = i32swp(item->priority);
                    item->con_size = i32swp(item->con_size);
                    item->args_size = i32swp(item->args_size);
                    item->flags = i32swp(item->flags);
                }
                sanitize_legacy_extra_item(item);
                if (!config->set_args && item->args_size > 0) {
                    config->set_args = (char *)item + sizeof(*item);
                }
                config->extra_type = item->type;
                config->data = (char *)item + sizeof(*item) + item->args_size;
                break;
            }
        }
        if (!item) tools_loge_exit("empty extra item\n");
        strcpy(item->magic, EXTRA_HDR_MAGIC);
        config->item = item;
        item->type = config->extra_type;
        if (config->set_args) item->args_size = align_ceil(strlen(config->set_args), EXTRA_ALIGN);
        if (config->set_name) strcpy(item->name, config->set_name);
        if (config->set_event) strcpy(item->event, config->set_event);
        if (config->priority) item->priority = config->priority;
    }

    qsort(extra_configs, extra_config_num, sizeof(extra_config_t), extra_compare);

    extra_size += sizeof(patch_extra_item_t); // ending with empty item

    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        extra_num++;
        extra_size += sizeof(patch_extra_item_t);
        extra_size += config->item->args_size;
        extra_size += config->item->con_size;
    }

    // copy to out image
    int ori_kimg_len = pimg.ori_kimg_len;
    int align_kimg_len = align_ceil(ori_kimg_len, SZ_4K);
    int out_img_len = align_kimg_len + kpimg_len;
    int out_all_len = out_img_len + extra_size;

    int start_offset = align_kernel_size;
    if (out_all_len > start_offset) {
        start_offset = align_ceil(out_all_len, SZ_4K);
        tools_logi("patch overlap, move start from 0x%x to 0x%x\n", align_kernel_size, start_offset);
    }
    tools_logi("layout kimg: 0x0,0x%x, kpimg: 0x%x,0x%x, extra: 0x%x,0x%x, end: 0x%x, start: 0x%x\n", ori_kimg_len,
               align_kimg_len, kpimg_len, out_img_len, extra_size, out_all_len, start_offset);

    kernel_file_t out_kernel_file;
    new_kernel_file(&out_kernel_file, &kernel_file, out_all_len, (bool)(is_be() ^ kinfo->is_be));
    memcpy(out_kernel_file.kimg, pimg.kimg, ori_kimg_len);
    memset(out_kernel_file.kimg + ori_kimg_len, 0, align_kimg_len - ori_kimg_len);
    memcpy(out_kernel_file.kimg + align_kimg_len, kpimg, kpimg_len);

    // set preset
    preset_t *preset = (preset_t *)(out_kernel_file.kimg + align_kimg_len);

    setup_header_t *header = &preset->header;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags & CONFIG_ANDROID;
    bool is_debug = header->config_flags & CONFIG_DEBUG;
    bool is_x86_64 = header->config_flags & CONFIG_FLAG_X86_64;
    tools_logi("kpimg version: %x\n", ver_num);
    tools_logi("kpimg compile time: %s\n", header->compile_time);
    tools_logi("kpimg config: %s, %s, %s\n", is_android ? "android" : "linux",
               is_debug ? "debug" : "release", is_x86_64 ? "x86_64" : "arm64");

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
    setup->start_offset = start_offset;
    setup->extra_size = extra_size;

    int map_start, map_max_size;
    select_map_area(&kallsym, kallsym_kimg, pimg.ori_kimg_len, &map_start, &map_max_size, is_gki);
    setup->map_offset = map_start;
    setup->map_max_size = map_max_size;
    tools_logi("map_start: 0x%x, max_size: 0x%x\n", map_start, map_max_size);

    int sync_start = map_start;
    int sync_size = map_max_size * 2;
    if (sync_start + sync_size > ori_kimg_len) {
        sync_size = ori_kimg_len - sync_start;
    }
    if (sync_size > 0) {
        memcpy(out_kernel_file.kimg + sync_start, kallsym_kimg + sync_start, sync_size);
        tools_logi("Synced NOP modifications from kallsym_kimg to output file (offset: 0x%x, size: 0x%x)\n", 
                   sync_start, sync_size);
    }

    const char *symbol_lookup_anchor_name = 0;
    setup->sprintf_offset = get_usable_symbol_offset_try(&kallsym, kallsym_kimg, ori_kimg_len, "sprintf");
    setup->symbol_lookup_anchor_offset =
        select_symbol_lookup_anchor_offset(&kallsym, kallsym_kimg, ori_kimg_len, &symbol_lookup_anchor_name);
    setup->kallsyms_lookup_name_offset =
        get_usable_symbol_offset_try(&kallsym, kallsym_kimg, ori_kimg_len, "kallsyms_lookup_name");
    if (setup->symbol_lookup_anchor_offset && setup->sprintf_offset) {
        tools_logi("prefer runtime forward scan anchor for kallsyms_lookup_name: %s, offset: 0x%08lx\n",
                   symbol_lookup_anchor_name, (unsigned long)setup->symbol_lookup_anchor_offset);
    } else if (setup->kallsyms_lookup_name_offset) {
        tools_logi("fallback to direct kallsyms_lookup_name symbol\n");
    } else {
        tools_loge_exit("no usable symbol scan anchor/sprintf chain and no kallsyms_lookup_name symbol\n");
    }

    setup->printk_offset = get_symbol_offset_zero(&kallsym, kallsym_kimg, "printk");
    if (!setup->printk_offset) setup->printk_offset = get_symbol_offset_zero(&kallsym, kallsym_kimg, "_printk");
    if (!setup->printk_offset) tools_loge_exit("no symbol printk\n");

    if ((is_be() ^ kinfo->is_be)) {
        setup->kimg_size = i64swp(setup->kimg_size);
        setup->kernel_size = i64swp(setup->kernel_size);
        setup->page_shift = i64swp(setup->page_shift);
        setup->setup_offset = i64swp(setup->setup_offset);
        setup->start_offset = i64swp(setup->start_offset);
        setup->extra_size = i64swp(setup->extra_size);
        setup->map_offset = i64swp(setup->map_offset);
        setup->map_max_size = i64swp(setup->map_max_size);
        setup->kallsyms_lookup_name_offset = i64swp(setup->kallsyms_lookup_name_offset);
        setup->sprintf_offset = i64swp(setup->sprintf_offset);
        setup->symbol_lookup_anchor_offset = i64swp(setup->symbol_lookup_anchor_offset);
        setup->paging_init_offset = i64swp(setup->paging_init_offset);
        setup->printk_offset = i64swp(setup->printk_offset);
    }

    // map symbol
    fillin_map_symbol(&kallsym, kallsym_kimg, &setup->map_symbol, kinfo->is_be);

    // header backup
    memcpy(setup->header_backup, kallsym_kimg, sizeof(setup->header_backup));

    // start symbol
    fillin_patch_config(&kallsym, kallsym_kimg, ori_kimg_len, &setup->patch_config, kinfo->is_be, 0);

    // superkey
    if (!root_key) {
        tools_logi("superkey: %s\n", superkey);
        strncpy((char *)setup->superkey, superkey, SUPER_KEY_LEN - 1);
    } else if (superkey && superkey[0] != '\0') {
        int len = SHA256_BLOCK_SIZE > ROOT_SUPER_KEY_HASH_LEN ? ROOT_SUPER_KEY_HASH_LEN : SHA256_BLOCK_SIZE;
        BYTE buf[SHA256_BLOCK_SIZE];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const BYTE *)superkey, strnlen(superkey, SUPER_KEY_LEN));
        sha256_final(&ctx, buf);
        memcpy(setup->root_superkey, buf, len);
        char *hexstr = bytes_to_hexstr(setup->root_superkey, len);
        tools_logi("root superkey hash: %s\n", hexstr);
        free(hexstr);
    } else {
        memset(setup->root_superkey, 0, ROOT_SUPER_KEY_HASH_LEN);
        tools_logi("root_key mode with empty superkey: root_superkey zeroed\n");
    }

    // modify kernel entry
    int paging_init_offset = get_symbol_offset_exit(&kallsym, kallsym_kimg, "paging_init");
    setup->paging_init_offset = relo_branch_func(kallsym_kimg, paging_init_offset);
    int text_offset = align_kimg_len + SZ_4K;
    b((uint32_t *)(out_kernel_file.kimg + kinfo->b_stext_insn_offset), kinfo->b_stext_insn_offset, text_offset);

    // additional [len key=value] set
    char *addition_pos = setup->additional;
    for (int i = 0;; i++) {
        const char *kv = additional[i];
        if (!kv) break;
        if (!strchr(kv, '=')) tools_loge_exit("addition must be format of key=value\n");

        int kvlen = strlen(kv);
        if (kvlen > 127) tools_loge_exit("addition %s too long\n", kv);
        if (addition_pos + kvlen + 1 > setup->additional + ADDITIONAL_LEN) tools_loge_exit("no memory for addition\n");

        *addition_pos = (char)kvlen;
        addition_pos++;

        tools_logi("adding addition: %s\n", kv);
        strcpy(addition_pos, kv);
        addition_pos += kvlen;
    }

// append extra
    int current_offset = out_img_len;
    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        patch_extra_item_t *item = config->item;
        const char *type = extra_type_str(item->type);
        tools_logi("embedding %s, name: %s, priority: %d, event: %s, args: %s, size: 0x%x+0x%x+0x%x\n", type,
                   item->name, item->priority, item->event, config->set_args ?: "", (int)sizeof(*item), item->args_size,
                   item->con_size);

        int args_len = item->args_size;
        int con_len = item->con_size;

        if (is_be() ^ kinfo->is_be) {
            item->type = i32swp(item->type);
            item->priority = i32swp(item->priority);
            item->con_size = i32swp(item->con_size);
            item->args_size = i32swp(item->args_size);
            item->flags = i32swp(item->flags);
        }

        extra_append(out_kernel_file.kimg, (void *)item, sizeof(*item), &current_offset);
        if (args_len > 0) extra_append(out_kernel_file.kimg, (void *)config->set_args, args_len, &current_offset);
        extra_append(out_kernel_file.kimg, (void *)config->data, con_len, &current_offset);
    }

    // record IKCONFIG gzip blob location for runtime puff inflation
    if (!kcfg_rc) {
        setup->kconfig_offset = (int64_t)kcfg_start;
        setup->kconfig_size = (int64_t)kcfg_bytes;
    }

    if ((is_be() ^ kinfo->is_be)) {
        setup->kconfig_offset = i64swp(setup->kconfig_offset);
        setup->kconfig_size = i64swp(setup->kconfig_size);
    }

    // guard extra
    patch_extra_item_t empty_item = { 0 };
    extra_append(out_kernel_file.kimg, (void *)&empty_item, sizeof(empty_item), &current_offset);

    write_kernel_file(&out_kernel_file, out_path);

    // free
    free(kallsym_kimg);
    free(kpimg);
    free_kernel_file(&out_kernel_file);
    free_kernel_file(&kernel_file);

    tools_logi("patch done: %s\n", out_path);

    set_log_enable(false);
    return 0;
}

int unpatch_img(const char *kimg_path, const char *out_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    if (!out_path) tools_loge_exit("empty out image path\n");

    char *probe = NULL;
    int probe_len = 0;
    read_file(kimg_path, &probe, &probe_len);
    bool x86_bzimage = is_x86_bzimage(probe, probe_len);
    free(probe);
    if (x86_bzimage) {
        set_log_enable(true);
        x86_bzimage_t image;
        if (load_x86_bzimage(kimg_path, &image)) {
            set_log_enable(false);
            return -1;
        }
        int rc = remove_x86_kpimg(&image);
        if (!rc) rc = write_x86_bzimage(&image, out_path);
        free_x86_bzimage(&image);
        set_log_enable(false);
        return rc;
    }

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    preset_t *preset = get_preset(kernel_file.kimg, kernel_file.kimg_len);
    if (!preset) tools_loge_exit("not patched kernel image\n");

    // todo: check whether the endian is different or not
    memcpy(kernel_file.kimg, preset->setup.header_backup, sizeof(preset->setup.header_backup));
    int kimg_size = preset->setup.kimg_size ?: ((char *)preset - kernel_file.kimg);
    update_kernel_file_img_len(&kernel_file, kimg_size, false);

    write_kernel_file(&kernel_file, out_path);
    free_kernel_file(&kernel_file);
    return 0;
}

int reset_key(const char *kimg_path, const char *out_path, const char *superkey)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    if (!out_path) tools_loge_exit("empty out image path\n");
    if (!superkey) tools_loge_exit("empty superkey\n");

    if (strlen(superkey) <= 0) tools_loge_exit("empty superkey\n");
    if (strlen(superkey) >= SUPER_KEY_LEN) tools_loge_exit("too long superkey\n");

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    preset_t *preset = get_preset(kernel_file.kimg, kernel_file.kimg_len);
    if (!preset) tools_loge_exit("not patched kernel image\n");

    char *origin_key = strdup((char *)preset->setup.superkey);
    strcpy((char *)preset->setup.superkey, superkey);
    tools_logi("reset superkey: %s -> %s\n", origin_key, preset->setup.superkey);

    write_kernel_file(&kernel_file, out_path);

    free(origin_key);
    free_kernel_file(&kernel_file);

    return 0;
}

int dump_kallsym(const char *kimg_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    set_log_enable(true);

    char *probe = 0;
    int probe_len = 0;
    read_file(kimg_path, &probe, &probe_len);
    bool bzimage = is_x86_bzimage(probe, probe_len);
    free(probe);
    if (bzimage) {
        x86_bzimage_t image;
        if (load_x86_bzimage(kimg_path, &image)) {
            fprintf(stderr, "load x86 bzImage error\n");
            return -1;
        }
        kallsym_t kallsym;
        int rc = analyze_kallsym_info(&kallsym, image.flat, image.flat_size, X86_64, 1);
        if (rc) {
            fprintf(stderr, "analyze x86 kallsyms error\n");
        } else {
            dump_all_symbols(&kallsym, image.flat);
        }
        free_x86_bzimage(&image);
        set_log_enable(false);
        return rc;
    }

    // read image files
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    kallsym_t kallsym;
    if (analyze_kallsym_info(&kallsym, kernel_file.kimg, kernel_file.kimg_len, ARM64, 1)) {
        fprintf(stdout, "analyze_kallsym_info error\n");
        return -1;
    }
    dump_all_symbols(&kallsym, kernel_file.kimg);
    set_log_enable(false);
    free_kernel_file(&kernel_file);
    return 0;
}
int dump_ikconfig(const char *kimg_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    set_log_enable(true);

    char *probe = 0;
    int probe_len = 0;
    read_file(kimg_path, &probe, &probe_len);
    bool bzimage = is_x86_bzimage(probe, probe_len);
    free(probe);
    if (bzimage) {
        x86_bzimage_t image;
        if (load_x86_bzimage(kimg_path, &image)) return -1;
        int rc = dump_all_ikconfig(image.flat, image.flat_size);
        free_x86_bzimage(&image);
        set_log_enable(false);
        return rc;
    }

    // read image files
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    
    dump_all_ikconfig(kernel_file.kimg,kernel_file.kimg_len);
    set_log_enable(false);
    free_kernel_file(&kernel_file);
    return 0;
}
