/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "symbol.h"
#include "common.h"

int32_t get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset(info, img, symbol);
    return offset > 0 ? offset : 0;
}

int32_t get_symbol_offset_exit(kallsym_t *info, char *img, char *symbol)
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

int32_t find_suffixed_symbol(kallsym_t *kallsym, char *img_buf, const char *symbol)
{
    struct on_each_symbol_struct udata = { symbol, 0 };
    on_each_symbol(kallsym, img_buf, &udata, on_each_symbol_callbackup);
    return udata.addr;
}

// todo
void select_map_area(kallsym_t *kallsym, char *image_buf, int32_t *map_start, int32_t *max_size)
{
    int32_t addr = 0x200;
    addr = get_symbol_offset_exit(kallsym, image_buf, "tcp_init_sock");
    *map_start = align_ceil(addr, 16);
    *max_size = 0x800;
}

int fillin_map_symbol(kallsym_t *kallsym, char *img_buf, map_symbol_t *symbol, int32_t target_is_be)
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

int fillin_patch_symbol(kallsym_t *kallsym, char *img_buf, patch_symbol_t *symbol, int32_t target_is_be,
                        bool is_android)
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
    if (!symbol->avc_denied && is_android) tools_error_exit("no symbol avc_denied");

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
