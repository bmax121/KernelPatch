/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "kpm.h"

#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)

static char *next_string(char *string, uint64_t *secsize)
{
    while (string[0]) {
        string++;
        if ((*secsize)-- <= 1) return 0;
    }
    while (!string[0]) {
        string++;
        if ((*secsize)-- <= 1) return 0;
    }
    return string;
}

static char *get_next_modinfo(const struct load_info *info, const char *tag, char *prev)
{
    char *p;
    uint32_t taglen = strlen(tag);
    Elf_Shdr *infosec = &info->sechdrs[info->index.info];
    uint64_t size = infosec->sh_size;
    char *modinfo = (char *)info->hdr + infosec->sh_offset;
    if (prev) {
        size -= prev - modinfo;
        modinfo = next_string(prev, &size);
    }
    for (p = modinfo; p; p = next_string(p, &size)) {
        if (strncmp(p, tag, taglen) == 0 && p[taglen] == '=') return p + taglen + 1;
    }
    return 0;
}

static char *get_modinfo(const struct load_info *info, const char *tag)
{
    return get_next_modinfo(info, tag, 0);
}

static int find_sec(const struct load_info *info, const char *name)
{
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if ((shdr->sh_flags & SHF_ALLOC) && strcmp(info->secstrings + shdr->sh_name, name) == 0) return i;
    }
    return 0;
}

static void *get_sh_base(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    void *addr = (void *)info->hdr + infosec->sh_offset;
    return addr;
}

static uint64_t get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return infosec->sh_entsize;
}

int get_kpm_info(const char *kpm, int len, kpm_info_t *out_info)
{
    struct load_info load_info = { .len = len, .hdr = (Elf_Ehdr *)kpm };
    struct load_info *info = &load_info;

    // header check
    if (info->len <= sizeof(*(info->hdr))) return -ENOEXEC;
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr))
        return -ENOEXEC;
    if (info->hdr->e_shoff >= info->len || (info->hdr->e_shnum * sizeof(Elf_Shdr) > info->len - info->hdr->e_shoff))
        return -ENOEXEC;

    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    info->secstrings = (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;
    info->sechdrs[0].sh_addr = 0;
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS && info->len < shdr->sh_offset + shdr->sh_size) {
            return -ENOEXEC;
        }
        shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
    }
    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        tools_loge("no .kpm.info section\n");
        return -ENOEXEC;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    out_info->name = get_modinfo(info, "name");
    out_info->version = get_modinfo(info, "version");
    out_info->license = get_modinfo(info, "license");
    out_info->author = get_modinfo(info, "author");
    out_info->description = get_modinfo(info, "description");

    return 0;
}

void print_kpm_info(kpm_info_t *info)
{
    fprintf(stdout, "name=%s\n", info->name);
    fprintf(stdout, "version=%s\n", info->version);
    fprintf(stdout, "license=%s\n", info->license);
    fprintf(stdout, "author=%s\n", info->author);
    fprintf(stdout, "description=%s\n", info->description);
}

int print_kpm_info_path(const char *kpm_path)
{
    char *img;
    int len = 0;
    read_file(kpm_path, &img, &len);
    fprintf(stdout, INFO_EXTRA_KPM_SESSION "\n");
    kpm_info_t kpm_info = { 0 };
    int rc = get_kpm_info(img, len, &kpm_info);
    if (!rc) {
        print_kpm_info(&kpm_info);
    }
    free(img);
    return rc;
}
