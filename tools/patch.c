/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "patch.h"
#include "kallsym.h"
#include "image.h"
#include "common.h"
#include "order.h"

#define SZ_4K 0x1000

#define align_floor(x, align) ((uint64_t)(x) & ~((uint64_t)(align)-1))
#define align_ceil(x, align) (((uint64_t)(x) + (uint64_t)(align)-1) & ~((uint64_t)(align)-1))

#define INSN_IS_B(inst) (((inst) & 0xFC000000) == 0x14000000)

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))

#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)

static int can_b_imm(uint64_t from, uint64_t to)
{
    // B: 128M
    uint32_t imm26 = 1 << 25 << 2;
    return (to >= from && to - from <= imm26) || (from >= to && from - to <= imm26);
}

static int b(uint32_t *buf, uint64_t from, uint64_t to)
{
    if (can_b_imm(from, to)) {
        buf[0] = 0x14000000u | (((to - from) & 0x0FFFFFFFu) >> 2u);
        return 4;
    }
    return 0;
}

preset_t *get_preset(const char *k_img, int k_img_len)
{
    char magic[MAGIC_LEN] = "KP1158";
    return (preset_t *)memmem(k_img, k_img_len, magic, sizeof(magic));
}

static int read_img(const char *path, char **con, int *len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) tools_error_exit("open file: %s, %s\n", path, strerror(errno));
    fseek(fp, 0, SEEK_END);
    long img_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = (char *)malloc(img_len);
    int readlen = fread(buf, 1, img_len, fp);
    if (readlen != img_len) tools_error_exit("read file: %s incomplete\n", path);
    fclose(fp);
    *con = buf;
    *len = img_len;
    return 0;
}

static int write_img(const char *path, char *img, int len)
{
    FILE *fout = fopen(path, "wb");
    if (!fout) tools_error_exit("open %s %s\n", path, strerror(errno));
    int writelen = fwrite(img, 1, len, fout);
    if (writelen != len) tools_error_exit("write file: %s incomplete\n", path);
    fclose(fout);
    return 0;
}

static void print_kpimg_info(preset_t *preset)
{
    setup_header_t *header = &preset->header;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags | CONFIG_ANDROID;
    bool is_debug = header->config_flags | CONFIG_DEBUG;
    tools_logi("kpimg version: %x\n", ver_num);
    tools_logi("kpimg compile time: %s\n", header->compile_time);
    tools_logi("kpimg config: %s, %s\n", is_debug ? "debug" : "release", is_android ? "android" : "linux");
}

static int32_t relo_branch_func(const char *img, int32_t func_offset)
{
    uint32_t inst = *(uint32_t *)(img + func_offset);
    int32_t relo_offset = func_offset;
    if (INSN_IS_B(inst)) {
        uint64_t imm26 = bits32(inst, 25, 0);
        uint64_t imm64 = sign64_extend(imm26 << 2u, 28u);
        relo_offset = func_offset + (int32_t)imm64;
        tools_logi("relocate branch function 0x%x to 0x%x\n", func_offset, relo_offset);
    }
    return relo_offset;
}

static int32_t get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset(info, img, symbol);
    return offset > 0 ? offset : 0;
}

static int32_t get_symbol_offset_exit(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset(info, img, symbol);
    if (offset >= 0) {
        return offset;
    } else {
        tools_error_exit("no symbol %s\n", symbol);
    }
}

struct on_each_symbol_struct
{
    const char *symbol;
    uint64_t addr;
};

static int32_t on_each_symbol_callbackup(int32_t index, char type, const char *symbol, int32_t offset, void *userdata)
{
    struct on_each_symbol_struct *data = (struct on_each_symbol_struct *)userdata;
    int len = strlen(data->symbol);
    if (strstr(symbol, data->symbol) == symbol && (symbol[len] == '.' || symbol[len] == '$')) {
        tools_logi("%s -> %s: type: %c, offset: 0x%08x\n", data->symbol, symbol, type, offset);
        data->addr = offset;
        return 1;
    }
    return 0;
}

static int32_t find_suffixed_symbol(kallsym_t *kallsym, char *img_buf, const char *symbol)
{
    struct on_each_symbol_struct udata = { symbol, 0 };
    on_each_symbol(kallsym, img_buf, &udata, on_each_symbol_callbackup);
    return udata.addr;
}

// todo
static void select_map_area(kallsym_t *kallsym, char *image_buf, int32_t *map_start, int32_t *max_size)
{
    int32_t addr = 0x200;
    addr = get_symbol_offset_exit(kallsym, image_buf, "tcp_init_sock");
    *map_start = align_ceil(addr, 16);
    *max_size = 0x800;
}

static int fillin_map_symbol(kallsym_t *kallsym, char *img_buf, map_symbol_t *symbol, int32_t target_is_be)
{
    symbol->memblock_reserve_relo = get_symbol_offset_exit(kallsym, img_buf, "memblock_reserve");
    symbol->memblock_free_relo = get_symbol_offset_exit(kallsym, img_buf, "memblock_free");

    symbol->memblock_mark_nomap_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_mark_nomap");

    symbol->memblock_phys_alloc_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_phys_alloc_try_nid");
    symbol->memblock_virt_alloc_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_virt_alloc_try_nid");
    if (!symbol->memblock_phys_alloc_relo && !symbol->memblock_virt_alloc_relo)
        tools_error_exit("no symbol memblock_alloc");

    uint64_t memblock_alloc_try_nid = get_symbol_offset_zero(kallsym, img_buf, "memblock_alloc_try_nid");

    if (!symbol->memblock_phys_alloc_relo) symbol->memblock_phys_alloc_relo = memblock_alloc_try_nid;
    if (!symbol->memblock_virt_alloc_relo) symbol->memblock_virt_alloc_relo = memblock_alloc_try_nid;
    if (!symbol->memblock_phys_alloc_relo && !symbol->memblock_virt_alloc_relo)
        tools_error_exit("no symbol memblock_alloc");

    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos <= (int64_t *)symbol; pos++) {
            *pos = i64swp(*pos);
        }
    }
    return 0;
}

static int fillin_patch_symbol(kallsym_t *kallsym, char *img_buf, patch_symbol_t *symbol, int32_t target_is_be)
{
    symbol->panic = get_symbol_offset_zero(kallsym, img_buf, "panic");

    symbol->rest_init = get_symbol_offset_zero(kallsym, img_buf, "rest_init");
    symbol->cgroup_init = get_symbol_offset_zero(kallsym, img_buf, "cgroup_init");
    if (!symbol->rest_init && !symbol->cgroup_init) {
        symbol->rest_init = find_suffixed_symbol(kallsym, img_buf, "rest_init");
    }
    if (!symbol->rest_init && !symbol->cgroup_init) tools_error_exit("no symbol rest_init");

    symbol->kernel_init = get_symbol_offset_zero(kallsym, img_buf, "kernel_init");

    symbol->report_cfi_failure = get_symbol_offset_zero(kallsym, img_buf, "report_cfi_failure");
    symbol->__cfi_slowpath_diag = get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath_diag");
    symbol->__cfi_slowpath = get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath");

    symbol->copy_process = get_symbol_offset_zero(kallsym, img_buf, "copy_process");
    symbol->cgroup_post_fork = get_symbol_offset_zero(kallsym, img_buf, "cgroup_post_fork");
    if (!symbol->copy_process && !symbol->cgroup_post_fork) {
        symbol->copy_process = find_suffixed_symbol(kallsym, img_buf, "copy_process");
    }
    if (!symbol->copy_process && !symbol->cgroup_post_fork) tools_error_exit("no symbol copy_process");

    symbol->__do_execve_file = get_symbol_offset_zero(kallsym, img_buf, "__do_execve_file");
    symbol->do_execveat_common = get_symbol_offset_zero(kallsym, img_buf, "do_execveat_common");
    symbol->do_execve_common = get_symbol_offset_zero(kallsym, img_buf, "do_execve_common");
    if (!symbol->__do_execve_file && !symbol->do_execveat_common && !symbol->do_execve_common) {
        symbol->__do_execve_file = find_suffixed_symbol(kallsym, img_buf, "__do_execve_file");
        symbol->do_execveat_common = find_suffixed_symbol(kallsym, img_buf, "do_execveat_common");
        symbol->do_execve_common = find_suffixed_symbol(kallsym, img_buf, "do_execve_common");
    }
    if (!symbol->__do_execve_file && !symbol->do_execveat_common && !symbol->do_execve_common)
        tools_error_exit("no symbol execve");

    symbol->avc_denied = get_symbol_offset_zero(kallsym, img_buf, "avc_denied");
    if (!symbol->avc_denied) {
        // gcc -fipa-sra eg: avc_denied.isra.5
        symbol->avc_denied = find_suffixed_symbol(kallsym, img_buf, "avc_denied");
    }
    if (!symbol->avc_denied) tools_error_exit("no symbol avc_denied");

    symbol->slow_avc_audit = get_symbol_offset_zero(kallsym, img_buf, "slow_avc_audit");

    symbol->input_handle_event = get_symbol_offset_zero(kallsym, img_buf, "input_handle_event");

    symbol->vfs_statx = get_symbol_offset_zero(kallsym, img_buf, "vfs_statx");
    symbol->do_statx = get_symbol_offset_zero(kallsym, img_buf, "do_statx");
    symbol->vfs_fstatat = get_symbol_offset_zero(kallsym, img_buf, "vfs_fstatat");
    if (!symbol->vfs_statx && !symbol->do_statx && !symbol->vfs_fstatat) {
        symbol->vfs_statx = find_suffixed_symbol(kallsym, img_buf, "vfs_statx");
        symbol->do_statx = find_suffixed_symbol(kallsym, img_buf, "do_statx");
        symbol->vfs_fstatat = find_suffixed_symbol(kallsym, img_buf, "vfs_fstatat");
    }
    if (!symbol->vfs_statx && !symbol->do_statx && !symbol->vfs_fstatat) tools_error_exit("no symbol stat");

    symbol->do_faccessat = get_symbol_offset_zero(kallsym, img_buf, "do_faccessat");
    symbol->sys_faccessat = get_symbol_offset_zero(kallsym, img_buf, "sys_faccessat");
    if (!symbol->do_faccessat && !symbol->sys_faccessat) {
        symbol->do_faccessat = find_suffixed_symbol(kallsym, img_buf, "do_faccessat");
        symbol->sys_faccessat = find_suffixed_symbol(kallsym, img_buf, "sys_faccessat");
    }
    if (!symbol->do_faccessat && !symbol->sys_faccessat) tools_error_exit("no symbol accessat");

    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos <= (int64_t *)symbol; pos++) {
            *pos = i64swp(*pos);
        }
    }
    return 0;
}

int patch_img(const char *k_img_path, const char *kp_img_path, const char *out_path, const char *superkey)
{
    if (!k_img_path || !kp_img_path || !out_path || !superkey) tools_error_exit("empty args\n");
    if (strlen(superkey) <= 0) tools_error_exit("empty superkey\n");
    if (strlen(superkey) >= SUPER_KEY_LEN) tools_error_exit("too long superkey\n");

    // read image files
    char *k_img = NULL, *kp_img = NULL;
    int k_img_len = 0, kp_img_len = 0;

    read_img(k_img_path, &k_img, &k_img_len);
    read_img(kp_img_path, &kp_img, &kp_img_len);

    // kernel image infomation
    kernel_info_t kinfo;
    if (get_kernel_info(&kinfo, k_img, k_img_len)) tools_error_exit("get_kernel_info error\n");

    int kernel_size = kinfo.kernel_size;
    int align_kernel_size = align_ceil(kernel_size, SZ_4K);

    // new patch or update
    int align_k_img_len;
    preset_t *old_preset = get_preset(k_img, k_img_len);
    if (old_preset) {
        tools_logi("update image ...\n");
        align_k_img_len = (char *)old_preset - k_img;
        assert((align_k_img_len & (SZ_4K - 1)) == 0);
        k_img_len = align_k_img_len;
    } else {
        tools_logi("new image ...\n");
        align_k_img_len = align_ceil(k_img_len, SZ_4K);
    }

    // copy to out image
    int out_img_len = align_k_img_len + kp_img_len;
    char *out_img = (char *)malloc(out_img_len);
    memcpy(out_img, k_img, k_img_len);
    memset(out_img + k_img_len, 0, align_k_img_len - k_img_len);
    memcpy(out_img + align_k_img_len, kp_img, kp_img_len);

    // set preset
    kallsym_t kallsym;
    if (analyze_kallsym_info(&kallsym, k_img, k_img_len, ARM64, 1)) tools_error_exit("analyze_kallsym_info error\n");

    preset_t *preset = (preset_t *)(out_img + align_k_img_len);
    print_kpimg_info(preset);

    setup_preset_t *setup = &preset->setup;
    memset(setup, 0, sizeof(preset->setup));

    setup->kernel_version.major = kallsym.version.major;
    setup->kernel_version.minor = kallsym.version.minor;
    setup->kernel_version.patch = kallsym.version.patch;

    setup->image_size = old_preset ? old_preset->setup.image_size : k_img_len;
    printf("aaaaaaaaaaaaaa imagesize: %x\n", preset->setup.image_size);

    setup->kernel_size = kinfo.kernel_size;
    setup->page_shift = kinfo.page_shift;
    setup->kp_offset = align_k_img_len;
    setup->start_offset = align_kernel_size;

    int map_start, map_max_size;
    select_map_area(&kallsym, k_img, &map_start, &map_max_size);
    setup->map_offset = map_start;
    setup->map_max_size = map_max_size;
    tools_logi("map_start: 0x%x, max_size: 0x%x\n", map_start, map_max_size);

    setup->kallsyms_lookup_name_offset = get_symbol_offset_exit(&kallsym, k_img, "kallsyms_lookup_name");

    setup->printk_offset = get_symbol_offset_zero(&kallsym, k_img, "printk");
    if (!setup->printk_offset) setup->printk_offset = get_symbol_offset_zero(&kallsym, k_img, "_printk");
    if (!setup->printk_offset) tools_error_exit("no symbol printk\n");

    if ((is_be() ^ kinfo.is_be)) {
        setup->image_size = i32swp(setup->image_size);
        setup->kernel_size = i64swp(setup->kernel_size);
        setup->page_shift = i64swp(setup->page_shift);
        setup->kp_offset = i64swp(setup->kp_offset);
        setup->map_offset = i64swp(setup->map_offset);
        setup->map_max_size = i64swp(setup->map_max_size);
        setup->kallsyms_lookup_name_offset = i64swp(setup->kallsyms_lookup_name_offset);
        setup->paging_init_offset = i64swp(setup->paging_init_offset);
        setup->printk_offset = i64swp(setup->printk_offset);
    }

    // map symbol
    fillin_map_symbol(&kallsym, k_img, &setup->map_symbol, kinfo.is_be);

    // header backup
    memcpy(setup->header_backup, k_img, sizeof(setup->header_backup));

    // start symbol
    fillin_patch_symbol(&kallsym, k_img, &setup->patch_symbol, kinfo.is_be);

    // superkey
    strncpy((char *)setup->superkey, superkey, SUPER_KEY_LEN - 1);
    tools_logi("superkey: %s\n", setup->superkey);

    // config
    patch_config_t *config = &setup->patch_config;
    if (preset->header.config_flags | CONFIG_ANDROID) {
        strncpy(config->config_reserved, "/data/adb/ap/init.ini", sizeof(config->config_reserved) - 1);
    } else {
        strncpy(config->config_reserved, "/etc/kp/init.ini", sizeof(config->config_reserved) - 1);
    }

    // modify kernel entry
    int paging_init_offset = get_symbol_offset_exit(&kallsym, k_img, "paging_init");
    setup->paging_init_offset = relo_branch_func(k_img, paging_init_offset);
    int text_offset = align_k_img_len + SZ_4K;
    b((uint32_t *)(out_img + kinfo.b_stext_insn_offset), kinfo.b_stext_insn_offset, text_offset);

    // write out
    write_img(out_path, out_img, out_img_len);

    // free
    free(k_img);
    free(kp_img);
    free(out_img);

    tools_logi("patch done: %s\n", out_path);

    return 0;
}

int unpatch_img(const char *k_img_path, const char *out_path)
{
    if (!k_img_path || !out_path) tools_error_exit("empty args\n");
    char *k_img = NULL;
    int k_img_len = 0;
    read_img(k_img_path, &k_img, &k_img_len);
    preset_t *preset = get_preset(k_img, k_img_len);
    if (!preset) tools_error_exit("not patched kernel image\n");
    printf("aaaaaaaaaaaaaa imagesize: %x\n", preset->setup.image_size);
    int image_size = preset->setup.image_size ?: ((char *)preset - k_img);
    printf("aaaaaaaaaaaaaa imagesize: %x\n", image_size);
    write_img(out_path, k_img, image_size);
    free(k_img);
    return 0;
}

int reset_key(const char *k_img_path, const char *out_path, const char *superkey)
{
    if (!k_img_path || !out_path || !superkey) tools_error_exit("empty args\n");
    if (strlen(superkey) <= 0) tools_error_exit("empty superkey\n");
    if (strlen(superkey) >= SUPER_KEY_LEN) tools_error_exit("too long superkey\n");

    char *k_img = NULL;
    int k_img_len = 0;
    read_img(k_img_path, &k_img, &k_img_len);

    preset_t *preset = get_preset(k_img, k_img_len);
    if (!preset) tools_error_exit("not patched kernel image\n");

    char *origin_key = strdup((char *)preset->setup.superkey);
    strcpy((char *)preset->setup.superkey, superkey);
    tools_logi("reset superkey: %s -> %s\n", origin_key, preset->setup.superkey);

    write_img(out_path, k_img, k_img_len);

    free(origin_key);
    free(k_img);

    return 0;
}

int dump_kallsym(const char *k_img_path)
{
    // read image files
    char *k_img = NULL;
    int k_img_len = 0;
    read_img(k_img_path, &k_img, &k_img_len);

    kallsym_t kallsym;
    if (analyze_kallsym_info(&kallsym, k_img, k_img_len, ARM64, 1)) {
        fprintf(stdout, "analyze_kallsym_info error\n");
        return -1;
    }
    dump_all_symbols(&kallsym, k_img);
    free(k_img);
    return 0;
}