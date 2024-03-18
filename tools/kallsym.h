/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_KALLSYM_H_
#define _KP_TOOL_KALLSYM_H_

#include <stdint.h>

// script/kallsym.c
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define KSYM_TOKEN_NUMS 256
#define KSYM_SYMBOL_LEN 512

#define KSYM_MIN_NEQ_SYMS 25600
#define KSYM_MIN_MARKER (KSYM_MIN_NEQ_SYMS / 256)
#define KSYM_FIND_NAMES_USED_MARKER 5

#define ARM64_RELO_MIN_NUM 4000

enum ksym_type
{
    // Seen in actual kernels
    ABSOLUTE = 'A',
    BSS = 'B',
    DATA = 'D',
    RODATA = 'R',
    TEXT = 'T',
    WEAK_OBJECT_WITH_DEFAULT = 'V',
    WEAK_SYMBOL_WITH_DEFAULT = 'W',
    // Seen on nm's manpage
    SMALL_DATA = 'G',
    INDIRECT_FUNCTION = 'I',
    DEBUGGING = 'N',
    STACK_UNWIND = 'P',
    COMMON = 'C',
    SMALL_BSS = 'S',
    UNDEFINED = 'U',
    UNIQUE_GLOBAL = 'u',
    WEAK_OBJECT = 'v',
    WEAK_SYMBOL = 'w',
    STABS_DEBUG = '-',
    UNKNOWN = '?',
};

enum arch_type
{
    ARM64 = 1,
    X86_64,
    ARM_BE,
    ARM_LE,
    X86
};

#define ELF64_KERNEL_MIN_VA 0xffffff8008080000
#define ELF64_KERNEL_MAX_VA 0xffffffffffffffff

typedef struct
{
    enum arch_type arch;
    int32_t is_64;
    int32_t is_be;

    struct
    {
        uint8_t _;
        uint8_t patch;
        uint8_t minor;
        uint8_t major;
    } version;

    int32_t banner_num;
    int32_t linux_banner_offset[4];
    int32_t symbol_banner_idx;

    char *kallsyms_token_table[KSYM_TOKEN_NUMS];
    int32_t asm_long_size;
    int32_t asm_PTR_size;
    int32_t kallsyms_num_syms;

    int32_t has_relative_base;
    int32_t kallsyms_addresses_offset;
    int32_t kallsyms_offsets_offset;
    // int32_t kallsyms_relative_base_offset;  // maybe 0
    int32_t kallsyms_num_syms_offset;
    int32_t kallsyms_names_offset;
    int32_t kallsyms_markers_offset;
    //kallsyms_seqs_of_names  // todo: v6.2
    int32_t kallsyms_token_table_offset;
    int32_t kallsyms_token_index_offset;

    int32_t _approx_addresses_or_offsets_offset;
    int32_t _approx_addresses_or_offsets_end;
    int32_t _approx_addresses_or_offsets_num;
    int32_t _marker_num;

    int32_t try_relo;
    int32_t relo_applied;
    int32_t elf64_rela_num;
    int32_t elf64_rela_offset;
    uint64_t elf64_kernel_base;
    int32_t elf64_current_heuris;

} kallsym_t;

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

int analyze_kallsym_info(kallsym_t *info, char *img, int32_t imglen, enum arch_type arch, int32_t is_64);
int dump_all_symbols(kallsym_t *info, char *img);
int get_symbol_index_offset(kallsym_t *info, char *img, int32_t index);
int get_symbol_offset_and_size(kallsym_t *info, char *img, char *symbol, int32_t *size);
int get_symbol_offset(kallsym_t *info, char *img, char *symbol);
int on_each_symbol(kallsym_t *info, char *img, void *userdata,
                   int32_t (*fn)(int32_t index, char type, const char *symbol, int32_t offset, void *userdata));

#endif // _KALLSYM_H_
