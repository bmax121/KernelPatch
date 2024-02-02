/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_KPM_H_
#define _KP_TOOL_KPM_H_

#include "elf/elf.h"
#include "common.h"

#define Elf_Shdr Elf64_Shdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Dyn Elf64_Dyn
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Addr Elf64_Addr
#ifdef CONFIG_MODULES_USE_ELF_REL
#define Elf_Rel Elf64_Rel
#endif
#ifdef CONFIG_MODULES_USE_ELF_RELA
#define Elf_Rela Elf64_Rela
#endif
#define ELF_R_TYPE(X) ELF64_R_TYPE(X)
#define ELF_R_SYM(X) ELF64_R_SYM(X)

#define INFO_EXTRA_KPM_SESSION "[kpm]"

struct load_info
{
    struct
    {
        const char *base;
        uint64_t size;
        const char *name, *version, *license, *author, *description;
    } info;
    Elf_Ehdr *hdr;
    uint64_t len;
    Elf_Shdr *sechdrs;
    char *secstrings, *strtab;
    uint64_t symoffs, stroffs;
    struct
    {
        uint32_t sym, str, mod, info;
    } index;
};

typedef struct
{
    const char *name, *version, *license, *author, *description;
} kpm_info_t;

int get_kpm_info(const char *kpm, int len, kpm_info_t *info);

void print_kpm_info(kpm_info_t *info);
int print_kpm_info_path(const char *kpm_path);

#endif