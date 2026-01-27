/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#define _GNU_SOURCE
#define __USE_GNU

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "kallsym.h"
#include "order.h"
#include "insn.h"
#include "common.h"

#define IKCFG_ST "IKCFG_ST"
#define IKCFG_ED "IKCFG_ED"
#include "zlib.h"

#define STRICTER_KALLSYMS 1

#ifdef _WIN32
#include <string.h>
static void *memmem(const void *haystack, size_t haystack_len, const void *const needle, const size_t needle_len)
{
    if (haystack == NULL) return NULL; // or assert(haystack != NULL);
    if (haystack_len == 0) return NULL;
    if (needle == NULL) return NULL; // or assert(needle != NULL);
    if (needle_len == 0) return NULL;

    for (const char *h = haystack; haystack_len >= needle_len; ++h, --haystack_len) {
        if (!memcmp(h, needle, needle_len)) {
            return (void *)h;
        }
    }
    return NULL;
}
#endif

static int find_linux_banner(kallsym_t *info, char *img, int32_t imglen)
{
    /*
	// todo: linux_proc_banner
  const char linux_banner[] =
        "Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@"
        LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n";
  Linux version 4.9.270-g862f51bac900-ab7613625 (android-build@abfarm-east4-101)
  (Android (7284624, based on r416183b) clang version 12.0.5
  (https://android.googlesource.com/toolchain/llvm-project
  c935d99d7cf2016289302412d708641d52d2f7ee)) #0 SMP PREEMPT Thu Aug 5 07:04:42
  UTC 2021
  */
    char linux_banner_prefix[] = "Linux version ";
    size_t prefix_len = strlen(linux_banner_prefix);

    char *imgend = img + imglen;
    char *banner = (char *)img;
    info->banner_num = 0;
    while ((banner = (char *)memmem(banner + 1, imgend - banner - 1, linux_banner_prefix, prefix_len)) != NULL) {
        if (isdigit(*(banner + prefix_len)) && *(banner + prefix_len + 1) == '.') {
            info->linux_banner_offset[info->banner_num++] = (int32_t)(banner - img);
            tools_logi("linux_banner %d: %s", info->banner_num, banner);
            tools_logi("linux_banner offset: 0x%lx\n", banner - img);
        }
    }
    banner = img + info->linux_banner_offset[info->banner_num - 1];

    char *uts_release_start = banner + prefix_len;
    char *space = strchr(banner + prefix_len, ' ');

    char *dot = NULL;

    // VERSION
    info->version.major = (uint8_t)strtoul(uts_release_start, &dot, 10);
    // PATCHLEVEL
    info->version.minor = (uint8_t)strtoul(dot + 1, &dot, 10);
    // SUBLEVEL
    int32_t patch = (int32_t)strtoul(dot + 1, &dot, 10);
    info->version.patch = patch <= 256 ? patch : 255;

    tools_logi("kernel version major: %d, minor: %d, patch: %d\n", info->version.major, info->version.minor,
               info->version.patch);
    return 0;
}

int kernel_if_need_patch(kallsym_t *info, char *img, int32_t imglen)
{
    char linux_banner_prefix[] = "Linux version ";
    size_t prefix_len = strlen(linux_banner_prefix);

    char *imgend = img + imglen;
    char *banner = (char *)img;
    info->banner_num = 0;
    while ((banner = (char *)memmem(banner + 1, imgend - banner - 1, linux_banner_prefix, prefix_len)) != NULL) {
        if (isdigit(*(banner + prefix_len)) && *(banner + prefix_len + 1) == '.') {
            info->linux_banner_offset[info->banner_num++] = (int32_t)(banner - img);
        }
    }
    banner = img + info->linux_banner_offset[info->banner_num - 1];

    char *uts_release_start = banner + prefix_len;
    char *space = strchr(banner + prefix_len, ' ');

    char *dot = NULL;

    // VERSION
    info->version.major = (uint8_t)strtoul(uts_release_start, &dot, 10);
    // PATCHLEVEL
    info->version.minor = (uint8_t)strtoul(dot + 1, &dot, 10);
    // SUBLEVEL
    int32_t patch = (int32_t)strtoul(dot + 1, &dot, 10);
    info->version.patch = patch <= 256 ? patch : 255;

    if (info->version.major < 6)return 0;
    if (info->version.minor < 7)return 0;
    return 1;
}

static int dump_kernel_config(kallsym_t *info, char *img, int32_t imglen)
{
    // todo:
    /*
  kernel configuration
  when CONFIG_IKCONFIG is enabled
  archived in GZip format between the magic string 'IKCFG_ST' and 'IKCFG_ED' in
  the built kernel.
  */
    tools_logw("not implemented\n");
    return 0;
}

static int find_token_table(kallsym_t *info, char *img, int32_t imglen)
{
    char nums_syms[20] = { '\0' };
    for (int32_t i = 0; i < 10; i++)
        nums_syms[i * 2] = '0' + i;

    // We just check first 10 letters, not all letters are guaranteed to appear,
    // In fact, the previous numbers may not always appear too.
    char letters_syms[20] = { '\0' };
    for (int32_t i = 0; i < 10; i++)
        letters_syms[i * 2] = 'a' + i;

    char *pos = img;
    char *num_start = NULL;
    char *imgend = img + imglen;
    for (; pos < imgend; pos = num_start + 1) {
        num_start = (char *)memmem(pos, imgend - pos, nums_syms, sizeof(nums_syms));
        if (!num_start) {
            tools_loge("find token_table error\n");
            return -1;
        }
        char *num_end = num_start + sizeof(nums_syms);
        if (!*num_end || !*(num_end + 1)) continue;

        char *letter = num_end;
        for (int32_t i = 0; letter < imgend && i < 'a' - '9' - 1; letter++) {
            if (!*letter) i++;
        }
        if (letter != (char *)memmem(letter, sizeof(letters_syms), letters_syms, sizeof(letters_syms))) continue;
        break;
    }

    // backward to start
    pos = num_start;
    for (int32_t i = 0; pos > img && i < '0' + 1; pos--) {
        if (!*pos) i++;
    }
    int32_t offset = pos + 2 - img;

    // align
    offset = align_ceil(offset, 4);

    info->kallsyms_token_table_offset = offset;

    tools_logi("kallsyms_token_table offset: 0x%08x\n", offset);

    // rebuild token_table
    pos = img + info->kallsyms_token_table_offset;
    for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
        info->kallsyms_token_table[i] = pos;
        while (*(pos++)) {
        };
    }
    // tools_logi("token table: ");
    // for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
    //   printf("%s ", info->kallsyms_token_table[i]);
    // }
    // printf("\n");
    return 0;
}

static int find_token_index(kallsym_t *info, char *img, int32_t imglen)
{
    uint16_t le_index[KSYM_TOKEN_NUMS] = { 0 };
    uint16_t be_index[KSYM_TOKEN_NUMS] = { 0 };

    int32_t start = info->kallsyms_token_table_offset;
    int32_t offset = start;

    // build kallsyms_token_index according to kallsyms_token_table
    for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
        uint16_t token_index = offset - start;
        le_index[i] = u16le(token_index);
        be_index[i] = u16be(token_index);
        while (img[offset++]) {
        };
    }
    // find kallsyms_token_index
    char *lepos = (char *)memmem(img, imglen, le_index, sizeof(le_index));
    char *bepos = (char *)memmem(img, imglen, be_index, sizeof(be_index));

    if (!lepos && !bepos) {
        tools_loge("kallsyms_token_index error\n");
        return -1;
    }
    tools_logi("endian: %s\n", lepos ? "little" : "big");

    char *pos = lepos ? lepos : bepos;
    info->is_be = lepos ? 0 : 1;

    info->kallsyms_token_index_offset = pos - img;

    tools_logi("kallsyms_token_index offset: 0x%08x\n", info->kallsyms_token_index_offset);
    return 0;
}

static int get_markers_elem_size(kallsym_t *info)
{
    if (info->kallsyms_markers_elem_size) return info->kallsyms_markers_elem_size;

    int32_t elem_size = info->asm_long_size;
    if (info->version.major < 4 || (info->version.major == 4 && info->version.minor < 20))
        elem_size = info->asm_PTR_size;

    return elem_size;
}

static int get_num_syms_elem_size(kallsym_t *info)
{
    // the same as kallsyms_markers
    int32_t elem_size = info->asm_long_size;
    if (info->version.major < 4 || (info->version.major == 4 && info->version.minor < 20))
        elem_size = info->asm_PTR_size;
    return elem_size;
}

static inline int get_addresses_elem_size(kallsym_t *info)
{
    return info->asm_PTR_size;
}

static inline int get_offsets_elem_size(kallsym_t *info)
{
    return info->asm_long_size;
}

static int try_find_arm64_relo_table(kallsym_t *info, char *img, int32_t imglen)
{
    if (!info->try_relo) return 0;

    uint64_t min_va = ELF64_KERNEL_MIN_VA;
    uint64_t max_va = ELF64_KERNEL_MAX_VA;
    uint64_t kernel_va = max_va;
    int32_t cand = 0;
    int rela_num = 0;
    while (cand < imglen - 24) {
        uint64_t r_offset = uint_unpack(img + cand, 8, info->is_be);
        uint64_t r_info = uint_unpack(img + cand + 8, 8, info->is_be);
        uint64_t r_addend = uint_unpack(img + cand + 16, 8, info->is_be);
        if ((r_offset & 0xffff000000000000) == 0xffff000000000000 && r_info == 0x403) {
            if (!(r_addend & 0xfff) && r_addend >= min_va && r_addend < kernel_va) kernel_va = r_addend;
            cand += 24;
            rela_num++;
        } else if (rela_num && !r_offset && !r_info && !r_addend) {
            cand += 24;
            rela_num++;
        } else {
            if (rela_num >= ARM64_RELO_MIN_NUM) break;
            cand += 8;
            rela_num = 0;
            kernel_va = max_va;
        }
    }

    if (info->kernel_base) {
        tools_logi("arm64 relocation kernel_va: 0x%" PRIx64 ", try: %" PRIx64 "\n", kernel_va, info->kernel_base);
        kernel_va = info->kernel_base;
    } else {
        info->kernel_base = kernel_va;
        tools_logi("arm64 relocation kernel_va: 0x%" PRIx64 "\n", kernel_va);
    }

    int32_t cand_start = cand - 24 * rela_num;
    int32_t cand_end = cand - 24;
    while (1) {
        if (*(uint64_t *)(img + cand_end) && *(uint64_t *)(img + cand_end + 8) && *(uint64_t *)(img + cand_end + 16))
            break;
        cand_end -= 24;
    }
    cand_end += 24;

    rela_num = (cand_end - cand_start) / 24;
    if (rela_num < ARM64_RELO_MIN_NUM) {
        tools_logw("can't find arm64 relocation table\n");
        return 0;
    }

    tools_logi("arm64 relocation table range: [0x%08x, 0x%08x), count: 0x%08x\n", cand_start, cand_end, rela_num);

    // apply relocations
    int32_t max_offset = imglen - 8;
    int32_t apply_num = 0;
    for (cand = cand_start; cand < cand_end; cand += 24) {
        uint64_t r_offset = uint_unpack(img + cand, 8, info->is_be);
        uint64_t r_info = uint_unpack(img + cand + 8, 8, info->is_be);
        uint64_t r_addend = uint_unpack(img + cand + 16, 8, info->is_be);
        if (!r_offset && !r_info && !r_addend) continue;
        if (r_offset <= kernel_va || r_offset >= max_va - imglen) {
            // tools_logw("warn ignore arm64 relocation r_offset: 0x%08lx at 0x%08x\n", r_offset, cand);
            continue;
        }

        int32_t offset = r_offset - kernel_va;
        if (offset < 0 || offset >= max_offset) {
            tools_logw("bad rela offset: 0x%" PRIx64 "\n", r_offset);
            info->try_relo = 0;
            return -1;
        }

        uint64_t value = uint_unpack(img + offset, 8, info->is_be);
        if (value == r_addend) continue;
        *(uint64_t *)(img + offset) = value + r_addend;
        apply_num++;
    }
    if (apply_num) apply_num--;
    tools_logi("apply 0x%08x relocation entries\n", apply_num);

    if (apply_num) info->relo_applied = 1;

#if 0
#include <stdio.h>
    FILE *frelo = fopen("./kernel.relo", "wb+");
    int w_len = fwrite(img, 1, imglen, frelo);
    tools_logi("===== write relo kernel image: %d ====\n", w_len);
    fclose(frelo);
#endif

    return 0;
}

static int find_approx_addresses(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t sym_num = 0;
    int32_t elem_size = info->asm_PTR_size;
    uint64_t prev_offset = 0;
    int32_t cand = 0;

    for (; cand < imglen - KSYM_MIN_NEQ_SYMS * elem_size; cand += elem_size) {
        uint64_t address = uint_unpack(img + cand, elem_size, info->is_be);
        if (!sym_num) { // first address
            if (address & 0xff) continue;
            if (elem_size == 4 && (address & 0xff800000) != 0xff800000) continue;
            if (elem_size == 8 && (address & 0xffff000000000000) != 0xffff000000000000) continue;
            prev_offset = address;
            sym_num++;
            continue;
        }
        if (address >= prev_offset) {
            prev_offset = address;
            if (sym_num++ >= KSYM_MIN_NEQ_SYMS) break;
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
    }
    if (sym_num < KSYM_MIN_NEQ_SYMS) {
        tools_loge("find approximate kallsyms_addresses error\n");
        return -1;
    }

    cand -= KSYM_MIN_NEQ_SYMS * elem_size;
    int32_t approx_offset = cand;
    info->_approx_addresses_or_offsets_offset = approx_offset;

    // approximate kallsyms_addresses end
    prev_offset = 0;
    for (; cand < imglen; cand += elem_size) {
        uint64_t offset = uint_unpack(img + cand, elem_size, info->is_be);
        if (offset < prev_offset) break;
        prev_offset = offset;
    }
    // end is not include
    info->_approx_addresses_or_offsets_end = cand;
    info->has_relative_base = 0;
    int32_t approx_num_syms = (cand - approx_offset) / elem_size;
    info->_approx_addresses_or_offsets_num = approx_num_syms;
    tools_logi("approximate kallsyms_addresses range: [0x%08x, 0x%08x) "
               "count: 0x%08x\n",
               approx_offset, cand, approx_num_syms);

    //
    if (info->relo_applied) {
        tools_logw("mismatch relo applied, subsequent operations may be undefined\n");
    }

    return 0;
}

static int find_approx_offsets(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t sym_num = 0;
    int32_t elem_size = info->asm_long_size;
    int64_t prev_offset = 0;
    int32_t cand = 0;
    int32_t MAX_ZERO_OFFSET_NUM = 10;
    int32_t zero_offset_num = 0;
    for (; cand < imglen - KSYM_MIN_NEQ_SYMS * elem_size; cand += elem_size) {
        int64_t offset = int_unpack(img + cand, elem_size, info->is_be);
        if (offset == prev_offset) { // 0 offset
            continue;
        } else if (offset > prev_offset) {
            prev_offset = offset;
            if (sym_num++ >= KSYM_MIN_NEQ_SYMS) break;
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
    }
    if (sym_num < KSYM_MIN_NEQ_SYMS) {
        tools_logw("find approximate kallsyms_offsets error\n");
        return -1;
    }
    cand -= KSYM_MIN_NEQ_SYMS * elem_size;
    for (;; cand -= elem_size)
        if (!int_unpack(img + cand, elem_size, info->is_be)) break;
    for (;; cand -= elem_size) {
        if (int_unpack(img + cand, elem_size, info->is_be)) break;
        if (zero_offset_num++ >= MAX_ZERO_OFFSET_NUM) break;
    }
    cand += elem_size;
    int32_t approx_offset = cand;
    info->_approx_addresses_or_offsets_offset = approx_offset;

    // approximate kallsyms_offsets end
    prev_offset = 0;
    for (; cand < imglen; cand += elem_size) {
        int64_t offset = int_unpack(img + cand, elem_size, info->is_be);
        if (offset < prev_offset) break;
        prev_offset = offset;
    }
    // the last symbol may not 4k alinged
    // end is not include
    int32_t end = cand;
    info->_approx_addresses_or_offsets_end = end;
    info->has_relative_base = 1;
    int32_t approx_num_syms = (end - approx_offset) / elem_size;
    info->_approx_addresses_or_offsets_num = approx_num_syms;
    // The real interval is contained in this approximate interval
    tools_logi("approximate kallsyms_offsets range: [0x%08x, 0x%08x) "
               "count: 0x%08x\n",
               approx_offset, end, approx_num_syms);
    return 0;
}

static int32_t find_approx_addresses_or_offset(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t ret = 0;
    if (info->version.major > 4 || (info->version.major == 4 && info->version.minor >= 6)) {
        // may have kallsyms_relative_base
        ret = find_approx_offsets(info, img, imglen);
        if (!ret) return 0;
    }
    ret = find_approx_addresses(info, img, imglen);
    return ret;
}

static int find_num_syms(kallsym_t *info, char *img, int32_t imglen)
{
#define NSYMS_MAX_GAP 10

    int32_t approx_end = info->kallsyms_names_offset;
    // int32_t num_syms_elem_size = get_num_syms_elem_size(info);
    int32_t num_syms_elem_size = 4;

    int32_t approx_num_syms = info->_approx_addresses_or_offsets_num;

    for (int32_t cand = approx_end; cand > approx_end - 4096; cand -= num_syms_elem_size) {
        int nsyms = (int)int_unpack(img + cand, num_syms_elem_size, info->is_be);
        if (!nsyms) continue;
        if (approx_num_syms > nsyms && approx_num_syms - nsyms > NSYMS_MAX_GAP) continue;
        if (nsyms > approx_num_syms && nsyms - approx_num_syms > NSYMS_MAX_GAP) continue;
        // find
        info->kallsyms_num_syms = nsyms;
        info->kallsyms_num_syms_offset = cand;
        break;
    }

    if (!info->kallsyms_num_syms_offset || !info->kallsyms_num_syms) {
#ifdef STRICTER_KALLSYMS
        // If we bail earlier here, we'll prevent kallsyms vector based fixup getting confused later
        return -1;
#endif
        info->kallsyms_num_syms = approx_num_syms - NSYMS_MAX_GAP;
        tools_logw("can't find kallsyms_num_syms, try: 0x%08x\n", info->kallsyms_num_syms);
    } else {
        tools_logi("kallsyms_num_syms offset: 0x%08x, value: 0x%08x\n", info->kallsyms_num_syms_offset,
                   info->kallsyms_num_syms);
    }
    return 0;
}

static int find_markers_internal(kallsym_t *info, char *img, int32_t imglen, int32_t elem_size)
{
    int32_t cand = info->kallsyms_token_table_offset;

    int64_t marker, last_marker = imglen;
    int count = 0;
    while (cand > 0x10000) {
        marker = int_unpack(img + cand, elem_size, info->is_be);
        if (last_marker > marker) {
            count++;
            if (!marker && count > KSYM_MIN_MARKER) break;
        } else {
            count = 0;
            last_marker = imglen;
        }

        last_marker = marker;
        cand -= elem_size;
    }

    if (count < KSYM_MIN_MARKER) {
        tools_logw("find kallsyms_markers error\n");
        return -1;
    }

    int32_t marker_end = cand + count * elem_size + elem_size;
    info->kallsyms_markers_offset = cand;
    info->_marker_num = count;
    info->kallsyms_markers_elem_size = elem_size;

    tools_logi("kallsyms_markers range: [0x%08x, 0x%08x), count: 0x%08x\n", cand, marker_end, count);
    return 0;
}

static int find_markers(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t elem_size = get_markers_elem_size(info);
    int rc = find_markers_internal(info, img, imglen, elem_size);
    if (rc && elem_size == 8) {
        return find_markers_internal(info, img, imglen, 4);
    }
    return rc;
}

static int decompress_symbol_name(kallsym_t *info, char *img, int32_t *pos_to_next, char *out_type, char *out_symbol)
{
    int32_t pos = *pos_to_next;
    int32_t len = *(uint8_t *)(img + pos++);
    if (len > 0x7F) len = (len & 0x7F) + (*(uint8_t *)(img + pos++) << 7);
    if (!len || len >= KSYM_SYMBOL_LEN) return -1;

    *pos_to_next = pos + len;
    for (int32_t i = 0; i < len; i++) {
        int32_t tokidx = *(uint8_t *)(img + pos + i);
        char *token = info->kallsyms_token_table[tokidx];
        if (!i) { // first character, symbol type
            if (out_type) *out_type = *token;
            token++;
        }
        if (out_symbol) strcat(out_symbol, token);
    }
    return 0;
}

static int is_symbol_name_pos(kallsym_t *info, char *img, int32_t pos, char *symbol)
{
    int32_t len = *(uint8_t *)(img + pos++);
    if (len > 0x7F) len = (len & 0x7F) + (*(uint8_t *)(img + pos++) << 7);
    if (!len || len >= KSYM_SYMBOL_LEN) return 0;
    int32_t symidx = 0;
    for (int32_t i = 0; i < len; i++) {
        int32_t tokidx = *(uint8_t *)(img + pos + i);
        char *token = info->kallsyms_token_table[tokidx];
        if (!i) token++; // ignore symbol type
        int32_t toklen = strlen(token);
        if (strncmp(symbol + symidx, token, toklen)) break;
        symidx += toklen;
    }
    return (int32_t)strlen(symbol) == symidx;
}

static int find_names(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t marker_elem_size = get_markers_elem_size(info);
    // int32_t cand = info->_approx_addresses_or_offsets_offset;
    int32_t cand = 0x4000;
    int32_t test_marker_num = -1;
    for (; cand < info->kallsyms_markers_offset; cand++) {
        int32_t pos = cand;
        test_marker_num = KSYM_FIND_NAMES_USED_MARKER; // check n * 256 symbols
        for (int32_t i = 0;; i++) {
            int32_t len = *(uint8_t *)(img + pos++);
            if (len > 0x7F) len = (len & 0x7F) + (*(uint8_t *)(img + pos++) << 7);
            if (!len || len >= KSYM_SYMBOL_LEN) break;
            pos += len;
            if (pos >= info->kallsyms_markers_offset) break;

            if (i && (i & 0xFF) == 0xFF) { // every 256 symbols
                int32_t mark_len = int_unpack(img + info->kallsyms_markers_offset + ((i >> 8) + 1) * marker_elem_size,
                                              marker_elem_size, info->is_be);
                if (pos - cand != mark_len) break;
                if (!--test_marker_num) break;
            }
        }
        if (!test_marker_num) break;
    }
    if (test_marker_num) {
        tools_loge("find kallsyms_names error\n");
        return -1;
    }
    info->kallsyms_names_offset = cand;
    tools_logi("kallsyms_names offset: 0x%08x\n", cand);

#if 0
    // print all symbol for test
    // if CONFIG_KALLSYMS=y and CONFIG_KALLSYMS_ALL=n
    // kallsyms_names table in kernel image will be truncated, and only functions exported
    int32_t pos = info->kallsyms_names_offset;
    int32_t index = 0;
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    while (pos < info->kallsyms_markers_offset) {
        memset(symbol, 0, sizeof(symbol));
        int32_t ret = decompress_symbol_name(info, img, &pos, NULL, symbol);
        if (ret) break;
        tools_logi("index: %d, %08x, symbol: %s\n", index, pos, symbol);
        index++;
    }
#endif
    return 0;
}

static int arm64_verify_pid_vnr(kallsym_t *info, char *img, int32_t offset)
{
    // prevent segfaults due to obviously wrong values, TBD: check kernel end
    if (offset < 0)
        return -1;
    for (int i = 0; i < 6; i++) {
        int32_t insn_offset = offset + i * 4;
        uint32_t insn = uint_unpack(img + insn_offset, 4, 0);
        enum aarch64_insn_encoding_class enc = aarch64_get_insn_class(insn);
        if (enc == AARCH64_INSN_CLS_BR_SYS) {
            if (aarch64_insn_extract_system_reg(insn) == AARCH64_INSN_SPCLREG_SP_EL0) {
                tools_logi("pid_vnr verfied sp_el0, insn: 0x%x\n", insn);
                info->current_type = SP_EL0;
                return 0;
            }
        } else if (enc == AARCH64_INSN_CLS_DP_IMM) {
            u32 rn = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, insn);
            if (rn == AARCH64_INSN_REG_SP) {
                tools_logi("pid_vnr verfied sp, insn: 0x%x\n", insn);
                info->current_type = SP;
                return 0;
            }
        }
    }
    return -1;
}

static int correct_addresses_or_offsets_by_vectors(kallsym_t *info, char *img, int32_t imglen)
{
    // vectors .align 11
    // todo: tramp_vectors .align 11
    int32_t pos = info->kallsyms_names_offset;
    int32_t index = 0, vector_index = 0, pid_vnr_index = 0;
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    while (pos < info->kallsyms_markers_offset) {
        memset(symbol, 0, sizeof(symbol));
        int32_t ret = decompress_symbol_name(info, img, &pos, NULL, symbol);
        if (ret) return ret;

        if (!vector_index && !strcmp(symbol, "vectors")) {
            vector_index = index;
        } else if (!pid_vnr_index && !strcmp(symbol, "pid_vnr")) {
            pid_vnr_index = index;
        }
        if (vector_index && pid_vnr_index) {
            tools_logi("names table vector index: 0x%08x, pid_vnr index: 0x%08x\n", vector_index, pid_vnr_index);
            break;
        }
        index++;
    }

    if (pos >= info->kallsyms_markers_offset) {
        tools_loge("no verify symbol in names table\n");
        return -1;
    }

    int32_t elem_size = info->has_relative_base ? get_offsets_elem_size(info) : get_addresses_elem_size(info);

    uint64_t base_cand[3] = { 0 };
    int base_cand_num = 1;

    if (!info->has_relative_base) {
        uint64_t base = uint_unpack(img + info->_approx_addresses_or_offsets_offset, elem_size, info->is_be);
        base_cand[0] = base;
        if (info->kernel_base) {
            base_cand[base_cand_num++] = info->kernel_base;
        }
        if (info->kernel_base != ELF64_KERNEL_MIN_VA) {
            base_cand[base_cand_num++] = ELF64_KERNEL_MIN_VA;
        }
    }

    int32_t search_start = info->_approx_addresses_or_offsets_offset;
    int32_t search_end = info->_approx_addresses_or_offsets_end - pid_vnr_index * elem_size;

    int break_flag = 0;
#if 0

    // If the 'vector' / 'pid_vnr' heuristic is failing, put first 10 entries from your kallsyms here.
    //
    // You can get it via
    // echo 0 > /proc/sys/kernel/kptr_restrict
    // head -10 /proc/kallsyms | awk '{printf "0x%s,", $1}' | sed '1s/^/{ /;$s/$/ }/'
    //
    // You'll need to temporarily use other root, ie magisk

    #define NOFS 10
    uint64_t ofs[NOFS] = { 0xffffff88c9481000,0xffffff88c9481000,0xffffff88c9481000,0xffffff88c94811c4,0xffffff88c948167c,0xffffff88c9481768,0xffffff88c94818a4,0xffffff88c9481944,0xffffff88c9481a2c,0xffffff88c9481c08, };

    // you may try to set search_start to 0 also
    for (pos = search_start; pos < search_end; pos += elem_size) {
        uint64_t first = uint_unpack(img + pos, elem_size, info->is_be) - ofs[0];
        for (int i = 1; i < NOFS; i++) {
            if ((uint_unpack(img + pos + i * elem_size, elem_size, info->is_be) - ofs[i]) != first) {
                goto gonext;
            }
        }
        break;
gonext:;
    }

    // if this fails, bail
    if (pos >= search_end) {
        tools_loge("can't locate kallsyms base (via explicit entry list)\n");
        return -1;
    }
#endif

#if 1
    for (int i = 0; i < base_cand_num; i++) {
        uint64_t base = base_cand[i];

        for (pos = search_start; pos < search_end; pos += elem_size) {
#ifdef STRICTER_KALLSYMS
            // HACK: Ensure first 3 kallsyms entries are the same
            uint64_t first = uint_unpack(img + pos, elem_size, info->is_be);
            for (int j = 1; j < 3; j++) {
                if (uint_unpack(img + pos + j * elem_size, elem_size, info->is_be) != first)
                    goto skip;
            }
#endif
            int32_t vector_offset = uint_unpack(img + pos + vector_index * elem_size, elem_size, info->is_be) - base;
            int32_t vector_next_offset =
                uint_unpack(img + pos + vector_index * elem_size + elem_size, elem_size, info->is_be) - base;
            if (vector_next_offset - vector_offset >= 0x600 && (vector_offset & ((1 << 11) - 1)) == 0) {
                int32_t pid_vnr_offset =
                    uint_unpack(img + pos + pid_vnr_index * elem_size, elem_size, info->is_be) - base;
                if (!arm64_verify_pid_vnr(info, img, pid_vnr_offset)) {
                    tools_logi("vectors index: %d, offset: 0x%08x\n", vector_index, vector_offset);
                    tools_logi("pid_vnr offset: 0x%08x\n", pid_vnr_offset);
                    info->kernel_base = base;
                    break_flag = 1;
                    break;
                }
            }
skip:;
        }

        if (break_flag) break;
    }
#endif

    if (pos >= search_end) {
        tools_loge("can't locate vectors\n");
        return -1;
    }

    if (info->has_relative_base) {
        info->kallsyms_offsets_offset = pos;
        tools_logi("kallsyms_offsets offset: 0x%08x\n", pos);
    } else {
        info->kallsyms_addresses_offset = pos;
        tools_logi("kallsyms_addresses offset: 0x%08x\n", pos);
        tools_logi("kernel base address: 0x%08llx\n", info->kernel_base);
    }

    return 0;
}

static int correct_addresses_or_offsets_by_banner(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t pos = info->kallsyms_names_offset;
    int32_t index = 0;
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };

    while (pos < info->kallsyms_markers_offset) {
        memset(symbol, 0, sizeof(symbol));
        int32_t ret = decompress_symbol_name(info, img, &pos, NULL, symbol);
        if (ret) return ret;

        if (!strcmp(symbol, "linux_banner")) {
            tools_logi("names table linux_banner index: 0x%08x\n", index);
            break;
        }
        if (!strcmp(symbol, "pid_vnr")) {
        }
        index++;
    }

    if (pos >= info->kallsyms_markers_offset) {
        tools_loge("no linux_banner in names table\n");
        return -1;
    }
    info->symbol_banner_idx = -1;

    // find correct addresses or offsets
    for (int i = 0; i < info->banner_num; i++) {
        int32_t target_offset = info->linux_banner_offset[i];

        int32_t elem_size = info->has_relative_base ? get_offsets_elem_size(info) : get_addresses_elem_size(info);
        pos = info->_approx_addresses_or_offsets_offset;

        int32_t end = pos + 4096 + elem_size;
        for (; pos < end; pos += elem_size) {
            uint64_t base = uint_unpack(img + pos, elem_size, info->is_be);
            int32_t offset = uint_unpack(img + pos + index * elem_size, elem_size, info->is_be) - base;
            if (offset == target_offset) break;
        }
        if (pos < end) {
            info->symbol_banner_idx = i;
            tools_logi("linux_banner index: %d\n", i);
            break;
        }
    }
    if (info->symbol_banner_idx < 0) {
        tools_loge("correct address or offsets error\n");
        return -1;
    }

    int32_t elem_size = info->has_relative_base ? get_offsets_elem_size(info) : get_addresses_elem_size(info);

    if (info->has_relative_base) {
        info->kallsyms_offsets_offset = pos;
        tools_logi("kallsyms_offsets offset: 0x%08x\n", pos);
    } else {
        info->kallsyms_addresses_offset = pos;
        tools_logi("kallsyms_addresses offset: 0x%08x\n", pos);
        info->kernel_base = uint_unpack(img + info->kallsyms_addresses_offset, elem_size, info->is_be);
        tools_logi("kernel base address: 0x%llx\n", info->kernel_base);
    }

    int32_t pid_vnr_offset = get_symbol_offset(info, img, "pid_vnr");
    if (arm64_verify_pid_vnr(info, img, pid_vnr_offset)) {
        tools_logw("pid_vnr verification failed\n");
    }

    return 0;
}

static int correct_addresses_or_offsets(kallsym_t *info, char *img, int32_t imglen)
{
    int rc = 0;
#if 1
    rc = correct_addresses_or_offsets_by_banner(info, img, imglen);
    info->is_kallsysms_all_yes = 1;
#endif
    if (rc) {
        info->is_kallsysms_all_yes = 0;
        tools_logw("no linux_banner, CONFIG_KALLSYMS_ALL=n\n");
    }
    if (rc) rc = correct_addresses_or_offsets_by_vectors(info, img, imglen);
    return rc;
}

void init_arm64_kallsym_t(kallsym_t *info)
{
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = 1;
    info->asm_long_size = 4;
    info->asm_PTR_size = 8;
    info->try_relo = 1;
}

void init_not_tested_arch_kallsym_t(kallsym_t *info, int32_t is_64)
{
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = is_64;
    info->asm_long_size = 4;
    info->asm_PTR_size = 4;
    info->try_relo = 0;
    if (is_64) info->asm_PTR_size = 8;
}

static int retry_relo(kallsym_t *info, char *img, int32_t imglen)
{
    int rc = -1;
    static int32_t (*funcs[])(kallsym_t *, char *, int32_t) = {
        try_find_arm64_relo_table,   find_markers, find_approx_addresses_or_offset, find_names, find_num_syms,
        correct_addresses_or_offsets
    };

    for (int i = 0; i < (int)(sizeof(funcs) / sizeof(funcs[0])); i++) {
        if ((rc = funcs[i](info, img, imglen))) break;
    }

    return rc;
}

/*
R kallsyms_offsets
R kallsyms_relative_base
R kallsyms_num_syms
R kallsyms_names
R kallsyms_markers
R kallsyms_token_table
R kallsyms_token_index
*/
int analyze_kallsym_info(kallsym_t *info, char *img, int32_t imglen, enum arch_type arch, int32_t is_64)
{
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = is_64;
    info->asm_long_size = 4;
    info->asm_PTR_size = 4;
    if (arch == ARM64) info->try_relo = 1;
    if (is_64) info->asm_PTR_size = 8;

    int rc = -1;
    static int32_t (*base_funcs[])(kallsym_t *, char *, int32_t) = {
        find_linux_banner,
        find_token_table,
        find_token_index,
    };
    for (int i = 0; i < (int)(sizeof(base_funcs) / sizeof(base_funcs[0])); i++) {
        if ((rc = base_funcs[i](info, img, imglen))) return rc;
    }

    char *copied_img = (char *)malloc(imglen);
    memcpy(copied_img, img, imglen);

    // 1st
    rc = retry_relo(info, copied_img, imglen);
    if (!rc) goto out;

    // 2nd
    if (!info->try_relo) {
        memcpy(copied_img, img, imglen);
        rc = retry_relo(info, copied_img, imglen);
        if (!rc) goto out;
    }

    // 3rd
    if (info->kernel_base != ELF64_KERNEL_MIN_VA) {
        info->kernel_base = ELF64_KERNEL_MIN_VA;
        memcpy(copied_img, img, imglen);
        rc = retry_relo(info, copied_img, imglen);
    }

out:
    memcpy(img, copied_img, imglen);
    free(copied_img);
    return rc;
}

int32_t get_symbol_index_offset(kallsym_t *info, char *img, int32_t index)
{
    int32_t elem_size;
    int32_t pos;
    if (info->has_relative_base) {
        elem_size = get_offsets_elem_size(info);
        pos = info->kallsyms_offsets_offset;
    } else {
        elem_size = get_addresses_elem_size(info);
        pos = info->kallsyms_addresses_offset;
    }
    uint64_t target = uint_unpack(img + pos + index * elem_size, elem_size, info->is_be);
    if (info->has_relative_base) return target;
    return (int32_t)(target - info->kernel_base);
}

int get_symbol_offset_and_size(kallsym_t *info, char *img, char *symbol, int32_t *size)
{
    char decomp[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    *size = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(decomp, 0, sizeof(decomp));
        decompress_symbol_name(info, img, &pos, &type, decomp);
        if (!strcmp(decomp, symbol)) {
            int32_t offset = get_symbol_index_offset(info, img, i);
            int32_t next_offset = offset;
            for (int32_t j = i + 1; j < info->kallsyms_num_syms; j++) {
                next_offset = get_symbol_index_offset(info, img, j);
                if (next_offset != offset) {
                    *size = next_offset - offset;
                    break;
                }
            }
            tools_logi("%s: type: %c, offset: 0x%08x, size: 0x%x\n", symbol, type, offset, *size);
            return offset;
        }
    }
    tools_logw("no symbol: %s\n", symbol);
    return -1;
}

int get_symbol_offset(kallsym_t *info, char *img, char *symbol)
{
    char decomp[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(decomp, 0, sizeof(decomp));
        decompress_symbol_name(info, img, &pos, &type, decomp);
        if (!strcmp(decomp, symbol)) {
            int32_t offset = get_symbol_index_offset(info, img, i);
            tools_logi("%s: type: %c, offset: 0x%08x\n", symbol, type, offset);
            return offset;
        }
    }
    tools_logw("no symbol: %s\n", symbol);
    return -1;
}

int dump_all_symbols(kallsym_t *info, char *img)
{
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(symbol, 0, sizeof(symbol));
        decompress_symbol_name(info, img, &pos, &type, symbol);
        int32_t offset = get_symbol_index_offset(info, img, i);
        fprintf(stdout, "0x%08x %c %s\n", offset, type, symbol);
    }
    return 0;
}
int decompress_data(const unsigned char *compressed_data, size_t compressed_size)
{
    FILE *temp = fopen("temp.gz", "wb");
    if (!temp) {
        fprintf(stderr, "Failed to create temp file\n");
        return -1;
    }

    fwrite(compressed_data, 1, compressed_size, temp);
    fclose(temp);

    gzFile gz = gzopen("temp.gz", "rb");
    if (!gz) {
        fprintf(stderr, "Failed to open temp file for decompression\n");
        return -1;
    }

    char buffer[1024];
    int bytes_read;
    while ((bytes_read = gzread(gz, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, bytes_read, stdout);
    }

    gzclose(gz);
    return 0;
}

int dump_all_ikconfig(char *img, int32_t imglen)
{
    char *pos_start = memmem(img, imglen, IKCFG_ST, strlen(IKCFG_ST));
    if (pos_start == NULL) {
        fprintf(stderr, "Cannot find kernel config start (IKCFG_ST).\n");
        return 1;
    }
    size_t kcfg_start = pos_start - img + 8;

    // 查找 "IKCFG_ED"
    char *pos_end = memmem(img, imglen, IKCFG_ED, strlen(IKCFG_ED));
    if (pos_end == NULL) {
        fprintf(stderr, "Cannot find kernel config end (IKCFG_ED).\n");
        return 1;
    }
    size_t kcfg_end = pos_end - img - 1;
    size_t kcfg_bytes = kcfg_end - kcfg_start + 1;

    printf("Kernel config start: %zu, end: %zu, bytes: %zu\n", kcfg_start, kcfg_end, kcfg_bytes);

    unsigned char *extracted_data = (unsigned char *)malloc(kcfg_bytes);
    if (!extracted_data) {
        fprintf(stderr, "Memory allocation for extracted data failed.\n");
        return 1;
    }

    memcpy(extracted_data, img + kcfg_start, kcfg_bytes);

    int ret = decompress_data(extracted_data, kcfg_bytes);

    free(extracted_data);

    return 0;
}

int on_each_symbol(kallsym_t *info, char *img, void *userdata,
                   int32_t (*fn)(int32_t index, char type, const char *symbol, int32_t offset, void *userdata))
{
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(symbol, 0, sizeof(symbol));
        decompress_symbol_name(info, img, &pos, &type, symbol);
        int32_t offset = get_symbol_index_offset(info, img, i);
        int rc = fn(i, type, symbol, offset, userdata);
        if (rc) return rc;
    }
    return 0;
}
