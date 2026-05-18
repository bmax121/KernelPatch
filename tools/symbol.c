/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "symbol.h"
#include "common.h"

struct on_each_symbol_struct
{
    const char *symbol;
    uint64_t addr;
};

static int32_t on_each_symbol_callbackup(int32_t index, char type, const char *symbol, int32_t offset, void *userdata)
{
    struct on_each_symbol_struct *data = (struct on_each_symbol_struct *)userdata;
    int len = strlen(data->symbol);
    if (strstr(symbol, data->symbol) == symbol && (symbol[len] == '.' || symbol[len] == '$') &&
        !strstr(symbol, ".cfi_jt")) {
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
        tools_loge_exit("no symbol %s\n", symbol);
    }
}

int32_t try_get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset(info, img, symbol);
    if (offset > 0) return offset;
    return find_suffixed_symbol(info, img, symbol);
}

static int get_cand_arr_symbol_offset_try(kallsym_t *kallsym, char *img_buf, const char **cand_arr, int cand_num,
                                          const char **selected)
{
    int offset = 0;

    for (int i = 0; i < cand_num; i++) {
        offset = try_get_symbol_offset_zero(kallsym, img_buf, (char *)cand_arr[i]);
        if (offset) {
            if (selected) *selected = cand_arr[i];
            return offset;
        }
    }

    if (selected) *selected = 0;
    return 0;
}

bool is_usable_symbol_offset(int32_t offset, int imglen)
{
    return imglen >= 0x1000 && offset > 0 && offset <= imglen - 0x1000;
}

int32_t get_usable_symbol_offset_try(kallsym_t *kallsym, char *img_buf, int imglen, const char *symbol)
{
    int32_t offset = get_symbol_offset_zero(kallsym, img_buf, (char *)symbol);
    if (is_usable_symbol_offset(offset, imglen)) {
        return offset;
    }

    offset = find_suffixed_symbol(kallsym, img_buf, symbol);
    if (is_usable_symbol_offset(offset, imglen)) {
        return offset;
    }

    return 0;
}

int32_t select_symbol_lookup_anchor_offset(kallsym_t *kallsym, char *img_buf, int imglen, const char **selected)
{
    static const char *anchor_candidates[] = {
        "show_stack",
        "dump_backtrace",
        "nmi_panic",
        "panic",
        "show_freq_kernel_log",
        "input_handle_event",
        "slow_avc_audit",
        "avc_denied",
        "tcp_init_sock",
        "udp_init_sock",
        "inet_create",
        "inet_release",
        "sock_init_data",
        "sk_alloc",
    };

    for (int i = 0; i < (int)(sizeof(anchor_candidates) / sizeof(anchor_candidates[0])); i++) {
        const char *name = anchor_candidates[i];
        int32_t offset = get_usable_symbol_offset_try(kallsym, img_buf, imglen, name);
        if (offset) {
            if (selected) *selected = name;
            return offset;
        }
    }

    if (selected) *selected = 0;
    return 0;
}

static int32_t get_map_anchor_offset(kallsym_t *kallsym, char *img_buf, int imglen, const char **selected)
{
    static const char *map_anchor_candidates[] = {
        "tcp_init_sock",
        "udp_init_sock",
        "inet_create",
        "inet_release",
        "sock_init_data",
        "sk_alloc",
        "input_handle_event",
        "slow_avc_audit",
        "avc_denied",
        "nmi_panic",
        "panic",
        "kern_addr_valid",
        "set_memory_rw",
        "set_memory_ro",
        "free_initmem",
    };

    for (int i = 0; i < (int)(sizeof(map_anchor_candidates) / sizeof(map_anchor_candidates[0])); i++) {
        const char *name = map_anchor_candidates[i];
        int32_t offset = get_usable_symbol_offset_try(kallsym, img_buf, imglen, name);
        if (offset) {
            if (selected) *selected = name;
            return offset;
        }
    }

    if (selected) *selected = 0;
    return 0;
}

// todo
void select_map_area(kallsym_t *kallsym, char *image_buf, int imglen, int32_t *map_start, int32_t *max_size, bool is_gki)
{
    const char *selected = 0;
    int32_t addr = get_map_anchor_offset(kallsym, image_buf, imglen, &selected);
    if (!addr) {
        tools_loge_exit("no usable map anchor symbol\n");
    }
    tools_logi("select map anchor: %s, offset: 0x%08x\n", selected, addr);

    if (!is_gki){
        // For non-GKI kernels, we can directly use the area starting from a cold text symbol for mapping.
        *map_start = align_ceil(addr, 16);
        *max_size = 0x800;
        return;
    }
    *map_start = align_floor(addr, 16);
    *max_size = 0x800;

#define NOP 0xD503201F
#define PAC 0xd503233f
#define AUT 0xd50323bf
#define PAC_MASK 0xFFFFFD1F
#define PAC_PATTERN 0xD503211F

    uint32_t pos = 0;
    uint32_t count = 0;
    uint32_t asmbit = sizeof(uint32_t);
    bool is_first_pac = false;
    for (uint32_t i = 0; i < *max_size; i += asmbit) {
        uint32_t insn = *(uint32_t *)(image_buf + addr + i);
        if (!is_first_pac && insn == PAC && i < asmbit * 5) {
            is_first_pac = true;
        }
        if ((insn & 0xFFFFFD1F) == 0xD503211F) {
            pos = i;
            count++;
            *(uint32_t *)(image_buf + addr + pos) = NOP;
        }
    }

    if (!is_first_pac) {
        tools_logi("no first pac instruction found \n");
    }

    if (count % 2 != 0) {
        tools_logi("pac verify not pair  pos: %x  count: %d\n", pos, count);

        uint32_t second_pos = 0;
        for (uint32_t j = *max_size; j < *max_size * 2; j += asmbit) {
            uint32_t insn = *(uint32_t *)(image_buf + addr + j);
            if ((insn & 0xFFFFFD1F) == 0xD503211F) {
                second_pos = j;
                break;
            }
        }
        tools_logi("second_pos: %x \n", second_pos);
        *(uint32_t *)(image_buf + addr + second_pos) = NOP;
    }

#undef NOP
#undef PAC
#undef AUT
#undef PAC_MASK
#undef PAC_PATTERN
}

int fillin_map_symbol(kallsym_t *kallsym, char *img_buf, map_symbol_t *symbol, int32_t target_is_be)
{
    bool use_legacy_memblock_fallback = false;

    symbol->memblock_reserve_relo = get_symbol_offset_exit(kallsym, img_buf, "memblock_reserve");
    symbol->memblock_free_relo = get_symbol_offset_exit(kallsym, img_buf, "memblock_free");

    symbol->memblock_mark_nomap_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_mark_nomap");

    symbol->memblock_phys_alloc_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_phys_alloc_try_nid");
    symbol->memblock_virt_alloc_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_virt_alloc_try_nid");
    uint64_t memblock_alloc_try_nid = get_symbol_offset_zero(kallsym, img_buf, "memblock_alloc_try_nid");
    if (!symbol->memblock_virt_alloc_relo) symbol->memblock_virt_alloc_relo = memblock_alloc_try_nid;

    if (!symbol->memblock_phys_alloc_relo) {
        symbol->memblock_phys_alloc_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_find_in_range");
        if (symbol->memblock_phys_alloc_relo) use_legacy_memblock_fallback = true;
    }

    if (use_legacy_memblock_fallback) {
        symbol->memblock_start_of_DRAM_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_start_of_DRAM");
    }

    if (!symbol->memblock_phys_alloc_relo) {
        tools_loge_exit("no symbol memblock alloc or memblock_find_in_range\n");
    }
    if (use_legacy_memblock_fallback && !symbol->memblock_start_of_DRAM_relo) {
         tools_loge_exit("no symbol memblock_start_of_DRAM for legacy memblock fallback\n");
    }

    if (use_legacy_memblock_fallback) {
        tools_logi("use legacy memblock fallback: memblock_find_in_range + memblock_start_of_DRAM\n");
    }

    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos < (int64_t *)((char *)symbol + sizeof(*symbol)); pos++) {
            *pos = i64swp(*pos);
        }
    }
    return 0;
}

static int get_cand_arr_symbol_offset_zero(kallsym_t *kallsym, char *img_buf, char **cand_arr, int cand_num)
{
    int offset = 0;
    for (int i = 0; i < cand_num; i++) {
        offset = get_symbol_offset_zero(kallsym, img_buf, cand_arr[i]);
        if (offset) break;
    }
    return offset;
}

int fillin_patch_config(kallsym_t *kallsym, char *img_buf, int imglen, patch_config_t *symbol, int32_t target_is_be,
                        bool is_android)
{
    symbol->kallsyms_lookup_name = get_usable_symbol_offset_try(kallsym, img_buf, imglen, "kallsyms_lookup_name");
    symbol->printk = get_symbol_offset_zero(kallsym, img_buf, "printk");
    if (!symbol->printk) symbol->printk = get_symbol_offset_zero(kallsym, img_buf, "_printk");
    if (!symbol->printk) tools_loge_exit("no symbol printk");

    symbol->panic = get_symbol_offset_zero(kallsym, img_buf, "panic");

    symbol->rest_init = try_get_symbol_offset_zero(kallsym, img_buf, "rest_init");
    if (!symbol->rest_init) symbol->cgroup_init = try_get_symbol_offset_zero(kallsym, img_buf, "cgroup_init");
    if (!symbol->rest_init && !symbol->cgroup_init) tools_loge_exit("no symbol rest_init");

    symbol->kernel_init = try_get_symbol_offset_zero(kallsym, img_buf, "kernel_init");

    symbol->report_cfi_failure = get_symbol_offset_zero(kallsym, img_buf, "report_cfi_failure");
    symbol->__cfi_slowpath_diag = get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath_diag");
    symbol->__cfi_slowpath = get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath");

    symbol->copy_process = try_get_symbol_offset_zero(kallsym, img_buf, "copy_process");
    if (!symbol->copy_process) symbol->cgroup_post_fork = get_symbol_offset_zero(kallsym, img_buf, "cgroup_post_fork");
    if (!symbol->copy_process && !symbol->cgroup_post_fork) tools_loge_exit("no symbol copy_process");

    //  gcc -fipa-sra eg: avc_denied.isra.5
    symbol->avc_denied = try_get_symbol_offset_zero(kallsym, img_buf, "avc_denied");
    if (!symbol->avc_denied && is_android) tools_loge_exit("no symbol avc_denied");

    symbol->slow_avc_audit = try_get_symbol_offset_zero(kallsym, img_buf, "slow_avc_audit");

    symbol->input_handle_event = get_symbol_offset_zero(kallsym, img_buf, "input_handle_event");

    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos <= (int64_t *)symbol; pos++) {
            *pos = i64swp(*pos);
        }
    }
    return 0;
}
