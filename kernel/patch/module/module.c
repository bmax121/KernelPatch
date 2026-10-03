/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <uapi/asm-generic/errno.h>
#include <pgtable.h>
#include <kpmalloc.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/string.h>
#include <symbol.h>
#include <kallsyms.h>
#include <cache.h>
#include <common.h>
#include <linux/fs.h>
#include <uapi/linux/fs.h>
#include <hotpatch.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>

#include "module.h"
#include "relo.h"
#include <kp_spinlock.h>
#include <kpmsymbol.h>

#define SZ_128M 0x08000000

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)

#define align(X) ALIGN(X, page_size)

#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)

#define ARCH_SHF_SMALL 0

static void set_load_error(struct load_info *info, const char *message)
{
    if (!info || !message) return;
    snprintf(info->info.error_msg, sizeof(info->info.error_msg), "%s", message);
}

static const char *load_error(const struct load_info *info, const char *fallback)
{
    if (info && info->info.error_msg[0]) return info->info.error_msg;
    return fallback;
}

static bool kpm_load_result_enabled(void __user *reserved)
{
    if (!reserved) return false;

    struct kpm_load_result *result = memdup_user(reserved, sizeof(*result));
    if (!result || IS_ERR(result)) return false;

    bool enabled = result->magic == KPM_LOAD_RESULT_MAGIC && result->size >= sizeof(*result);
    kvfree(result);
    return enabled;
}

static void set_kpm_load_result(void __user *reserved, long code, const char *message)
{
    if (!kpm_load_result_enabled(reserved)) return;

    struct kpm_load_result result;
    memset(&result, 0, sizeof(result));
    result.magic = KPM_LOAD_RESULT_MAGIC;
    result.size = sizeof(result);
    result.code = code;
    if (message) snprintf(result.message, sizeof(result.message), "%s", message);
    compat_copy_to_user(reserved, &result, sizeof(result));
}

static inline bool strstarts(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static char *next_string(char *string, unsigned long *secsize)
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

/* Update size with this section: return offset. */
static long get_offset(struct module *mod, unsigned int *size, Elf_Shdr *sechdr, unsigned int section)
{
    long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
    *size = ret + sechdr->sh_size;
    return ret;
}

static char *get_next_modinfo(const struct load_info *info, const char *tag, char *prev)
{
    char *p;
    unsigned int taglen = strlen(tag);
    Elf_Shdr *infosec = &info->sechdrs[info->index.info];
    unsigned long size = infosec->sh_size;
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

static unsigned long get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return infosec->sh_entsize;
}

static void layout_sections(struct module *mod, struct load_info *info)
{
    static unsigned long const masks[][2] = {
        /* NOTE: all executable code must be the first section in this array; otherwise modify the text_size finder in the two loops below */
        { SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
        { SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
        { SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
        { ARCH_SHF_SMALL | SHF_ALLOC, 0 }
    };

    for (int i = 0; i < info->hdr->e_shnum; i++)
        info->sechdrs[i].sh_entsize = ~0UL;

    // todo: tslf alloc all rwx and not page aligned
    for (int m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
        for (int i = 0; i < info->hdr->e_shnum; ++i) {
            Elf_Shdr *s = &info->sechdrs[i];
            if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
                continue;
            s->sh_entsize = get_offset(mod, &mod->size, s, i);
            // const char *sname = info->secstrings + s->sh_name;
        }
        switch (m) {
        case 0: /* executable */
            mod->size = align(mod->size);
            mod->text_size = mod->size;
            break;
        case 1: /* RO: text and ro-data */
            mod->size = align(mod->size);
            mod->ro_size = mod->size;
            break;
        case 2:
            break;
        case 3: /* whole */
            mod->size = align(mod->size);
            break;
        }
    }
}

static bool is_core_symbol(const Elf_Sym *src, const Elf_Shdr *sechdrs, unsigned int shnum)
{
    const Elf_Shdr *sec;
    if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name) return false;
    sec = sechdrs + src->st_shndx;
    if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR)) return false;
    return true;
}


extern struct module modules;
static spinlock_t module_lock;

/* LKM loader semantics: search the export tables of already-loaded KPMs
 * (.kpm.export / KPM_EXPORT) for @name and record the dependency edge on
 * @importer.  Runtime-table symbols win, exactly like vmlinux exports shadow
 * module exports in the kernel's find_symbol(). */
static unsigned long kpm_module_export_lookup(const char *name, struct module *importer)
{
    struct module *pos;
    unsigned long found = 0;
    unsigned long flags;

    if (!importer) return 0;
    flags = kp_private_spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) {
        unsigned int i;
        for (i = 0; i < pos->export_count; i++) {
            if (!strcmp(name, pos->exports[i].name)) {
                {
                    int edge = kpm_dep_record((void **)importer->deps, &importer->dep_count,
                                              KPM_DEP_MAX, pos);
                    if (edge < 0) {
                        /* Table full: fail the resolution so the KPM load aborts.
                         * Silently succeeding here would allow the provider to be
                         * unloaded while the consumer still holds its symbols. */
                        logke("dependency table full; cannot import %s from %s\n", name, pos->info.name);
                        goto out;
                    }
                    /* Pin the provider before returning its address.  The
                     * reference stays provisional through importer init and is
                     * rolled back if loading fails. */
                    if (edge > 0) pos->export_refs++;
                }
                found = (unsigned long)pos->exports[i].target;
                goto out;
            }
        }
    }
out:
    kp_private_spin_unlock(&module_lock, flags);
    return found;
}

static unsigned long kpm_compat_lookup(const char *name, void *context)
{
    unsigned long addr = symbol_lookup_name(name);
    if (addr) return addr;
    return kpm_module_export_lookup(name, context);
}

static unsigned long kpm_function_lookup(const char *name, void *context)
{
    (void)context;
    return kallsyms_lookup_name ? kallsyms_lookup_name_by_suffix(name) : 0;
}

static unsigned long kpm_data_lookup(const char *name, void *context)
{
    (void)context;
    return kallsyms_lookup_name ? kallsyms_lookup_name(name) : 0;
}

static unsigned long kpm_pointer_slot(unsigned long target, void *context)
{
    struct module *mod = context;
    return kpm_link_pointer(&mod->link, mod->start, target);
}

/* Reserve pointer slots and a worst-case PLT/GOT entry per allocated RELA. */
static int kpm_prepare_link(struct module *mod, const struct load_info *info)
{
    unsigned long count = info->sechdrs[info->index.sym].sh_size / sizeof(Elf_Sym);
    unsigned int i;
    if (count > KPM_LINK_MAX_IMAGE / KPM_LINK_SLOT_SIZE) return -E2BIG;
    for (i = 1; i < info->hdr->e_shnum; i++) {
        const Elf_Shdr *section = &info->sechdrs[i];
        if (section->sh_type != SHT_RELA || section->sh_info >= info->hdr->e_shnum ||
            !(info->sechdrs[section->sh_info].sh_flags & SHF_ALLOC)) continue;
        if (section->sh_size % sizeof(Elf64_Rela)) return -ENOEXEC;
        if (section->sh_size / sizeof(Elf64_Rela) > KPM_LINK_MAX_IMAGE / KPM_LINK_SLOT_SIZE - count)
            return -E2BIG;
        count += section->sh_size / sizeof(Elf64_Rela);
    }
    return kpm_link_reserve(&mod->link, &mod->size, count) ? -E2BIG : 0;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(struct module *mod, struct load_info *info)
{
    Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
    Elf_Sym *sym = (void *)symsec->sh_addr;
    unsigned long secbase;
    unsigned int i;
    int ret = 0;

    for (i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
        const char *name = info->strtab + sym[i].st_name;
        switch (sym[i].st_shndx) {
        case SHN_COMMON:
            set_load_error(info, "COMMON symbol unsupported: compile with -fno-common and without LTO");
            ret = -ENOEXEC;
            break;
        case SHN_ABS:
            break;
        case SHN_UNDEF: {
            struct kpm_symbol_resolution resolved;
            int rc = kpm_symbol_resolve(name, kpm_compat_lookup, kpm_function_lookup,
                                        kpm_data_lookup, kpm_pointer_slot, mod, &resolved);
            if (rc) {
                if (rc == -1 && ELF_ST_BIND(sym[i].st_info) == STB_WEAK) {
                    sym[i].st_value = 0;
                    break;
                }
                logke("unresolved symbol: %s (%s)\n", name,
                      rc == -2 ? "link arena exhausted" : "unavailable on this kernel");
                if (!info->info.error_msg[0])
                    snprintf(info->info.error_msg, sizeof(info->info.error_msg),
                             "unresolved symbol: %s (%s)", name,
                             rc == -2 ? "link arena exhausted" : "unavailable on this kernel");
                ret = rc == -2 ? -ENOMEM : -ENOENT;
                break;
            }
            sym[i].st_value = resolved.address;
            break;
        }
        default:
            if (sym[i].st_shndx >= info->hdr->e_shnum) {
                set_load_error(info, "invalid symbol section index");
                ret = -ENOEXEC;
                break;
            }
            secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
            sym[i].st_value += secbase;
            break;
        }
    }
    return ret;
}

static int apply_relocations(struct module *mod, const struct load_info *info)
{
    int rc = 0;
    unsigned int i;
    for (i = 1; i < info->hdr->e_shnum; i++) {
        unsigned int infosec = info->sechdrs[i].sh_info;
        if (infosec >= info->hdr->e_shnum) continue;
        if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC)) continue;
        if (info->sechdrs[i].sh_type == SHT_REL) {
            rc = apply_relocate(info->sechdrs, info->strtab, info->index.sym, i, mod);
        } else if (info->sechdrs[i].sh_type == SHT_RELA) {
            rc = apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
        }
        if (rc < 0) break;
    }
    return rc;
}

// todo: free .strtab and .symtab after relocation
static void layout_symtab(struct module *mod, struct load_info *info)
{
    Elf_Shdr *symsect = info->sechdrs + info->index.sym;
    Elf_Shdr *strsect = info->sechdrs + info->index.str;
    const Elf_Sym *src;
    unsigned int i, nsrc, ndst, strtab_size = 0;

    /* Put symbol section at end of module. */
    symsect->sh_flags |= SHF_ALLOC;
    symsect->sh_entsize = get_offset(mod, &mod->size, symsect, info->index.sym);

    src = (void *)info->hdr + symsect->sh_offset;
    nsrc = symsect->sh_size / sizeof(*src);

    /* strtab always starts with a nul, so offset 0 is the empty string. */
    strtab_size = 1;
    /* Compute total space required for the core symbols' strtab. */
    for (ndst = i = 0; i < nsrc; i++) {
        if (i == 0 || is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
            strtab_size += strlen(&info->strtab[src[i].st_name]) + 1;
            ndst++;
        }
    }

    /* Append room for core symbols at end. */
    info->symoffs = ALIGN(mod->size, symsect->sh_addralign ?: 1);
    info->stroffs = mod->size = info->symoffs + ndst * sizeof(Elf_Sym);
    mod->size += strtab_size;

    /* Put string table section at end of module. */
    strsect->sh_flags |= SHF_ALLOC;
    strsect->sh_entsize = get_offset(mod, &mod->size, strsect, info->index.str);
}

static int rewrite_section_headers(struct load_info *info)
{
    info->sechdrs[0].sh_addr = 0;
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        Elf_Shdr *strings = &info->sechdrs[info->hdr->e_shstrndx];
        if (shdr->sh_name >= strings->sh_size ||
            !memchr(info->secstrings + shdr->sh_name, 0, strings->sh_size - shdr->sh_name))
            return -ENOEXEC;
        if (shdr->sh_addralign && (shdr->sh_addralign & (shdr->sh_addralign - 1)))
            return -ENOEXEC;
        /* Subtraction, not sh_offset + sh_size: the sum can wrap for a
         * crafted 64-bit offset and let the bounds check pass. */
        if (shdr->sh_type != SHT_NOBITS &&
            (shdr->sh_offset > info->len || shdr->sh_size > info->len - shdr->sh_offset)) {
            return -ENOEXEC;
        }
        /* sh_name indexes the section string table; bound it before
         * move_module() hands the name to strcmp(). */
        {
            const Elf_Shdr *section_strings = &info->sechdrs[info->hdr->e_shstrndx];
            if (shdr->sh_name >= section_strings->sh_size ||
                !memchr(info->secstrings + shdr->sh_name, 0,
                        section_strings->sh_size - shdr->sh_name))
                return -ENOEXEC;
        }
        /* sh_name indexes the section string table; bound it before any
         * find_sec()/move_module() string operation consumes it. */
        {
            const Elf_Shdr *shstr = &info->sechdrs[info->hdr->e_shstrndx];
            if (shdr->sh_name >= shstr->sh_size ||
                !memchr(info->secstrings + shdr->sh_name, 0,
                        shstr->sh_size - shdr->sh_name))
                return -ENOEXEC;
        }
        if (shdr->sh_addralign && (shdr->sh_addralign & (shdr->sh_addralign - 1)))
            return -ENOEXEC;
        /* Mark all sections sh_addr with their address in the temporary image. */
        shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
    }
    return 0;
}

static int move_module(struct module *mod, struct load_info *info)
{
    // todo:
    logki("alloc module size: %llx\n", mod->size);
    mod->start = kp_malloc_exec(mod->size);
    if (!mod->start) {
        return -ENOMEM;
    }
    memset(mod->start, 0, mod->size);

    /* Transfer each section which specifies SHF_ALLOC */
    logkd("final section addresses:\n");

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        void *dest;
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;

        dest = mod->start + shdr->sh_entsize;
        const char *sname = info->secstrings + shdr->sh_name;

        logkd("    %s %llx %llx\n", sname, dest, shdr->sh_size);

        if (shdr->sh_type != SHT_NOBITS) memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

        shdr->sh_addr = (unsigned long)dest;

        if (!mod->init && !strcmp(".kpm.init", sname)) mod->init = (mod_initcall_t *)dest;

        if (!strcmp(".kpm.ctl0", sname)) mod->ctl0 = (mod_ctl0call_t *)dest;
        if (!strcmp(".kpm.ctl1", sname)) mod->ctl1 = (mod_ctl1call_t *)dest;

        if (!mod->exit && !strcmp(".kpm.exit", sname)) mod->exit = (mod_exitcall_t *)dest;
        if (!mod->event && !strcmp(".kpm.event", sname)) mod->event = (mod_eventcall_t *)dest;

        if (!mod->info.base && !strcmp(".kpm.info", sname)) mod->info.base = (const char *)dest;

        if (!mod->exports && !strcmp(".kpm.export", sname)) {
            mod->exports = (const struct kpm_export_entry *)dest;
            mod->export_count = shdr->sh_size / sizeof(struct kpm_export_entry);
        }
    }
    mod->info.name = info->info.name - info->info.base + mod->info.base;
    mod->info.version = info->info.version - info->info.base + mod->info.base;

    if (info->info.license) mod->info.license = info->info.license - info->info.base + mod->info.base;
    if (info->info.author) mod->info.author = info->info.author - info->info.base + mod->info.base;
    if (info->info.description) mod->info.description = info->info.description - info->info.base + mod->info.base;

    return 0;
}

static int setup_load_info(struct load_info *info)
{
    int rc = 0;
    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    if (!info->hdr->e_shstrndx || info->hdr->e_shstrndx >= info->hdr->e_shnum) {
        set_load_error(info, "invalid section string table index");
        return -ENOEXEC;
    }
    Elf_Shdr *section_strings = &info->sechdrs[info->hdr->e_shstrndx];
    if (section_strings->sh_type != SHT_STRTAB || section_strings->sh_offset > info->len ||
        section_strings->sh_size > info->len - section_strings->sh_offset) {
        set_load_error(info, "invalid section string table bounds");
        return -ENOEXEC;
    }
    info->secstrings = (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;

    if ((rc = rewrite_section_headers(info))) {
        logke("rewrite section error\n");
        set_load_error(info, "rewrite section headers failed");
        return rc;
    }

    if (!find_sec(info, ".kpm.init") || !find_sec(info, ".kpm.exit")) {
        logke("no .kpm.init or .kpm.exit section\n");
        set_load_error(info, "no .kpm.init or .kpm.exit section");
        return -ENOEXEC;
    }

    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        logke("no .kpm.info section\n");
        set_load_error(info, "no .kpm.info section");
        return -ENOEXEC;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    const char *name = get_modinfo(info, "name");
    if (!name) {
        logke("module name not found\n");
        set_load_error(info, "module name not found");
        return -ENOEXEC;
    }
    info->info.name = name;
    logkd("loading module: \n");
    logkd("    name: %s\n", name);

    const char *version = get_modinfo(info, "version");
    if (!version) {
        logkd("module version not found\n");
        set_load_error(info, "module version not found");
        return -ENOEXEC;
    }
    info->info.version = version;
    logkd("    version: %s\n", version);

    const char *license = get_modinfo(info, "license");
    info->info.license = license;
    logkd("    license: %s\n", license);

    const char *author = get_modinfo(info, "author");
    info->info.author = author;
    logkd("    author: %s\n", author);
    const char *description = get_modinfo(info, "description");
    info->info.description = description;
    logkd("    description: %s\n", description);

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
            info->index.sym = i;
            info->index.str = info->sechdrs[i].sh_link;
            if (info->index.str >= info->hdr->e_shnum) {
                set_load_error(info, "invalid symbol string section index");
                return -ENOEXEC;
            }
            info->strtab = (char *)info->hdr + info->sechdrs[info->index.str].sh_offset;
            break;
        }
    }

    if (info->index.sym == 0) {
        logkd("module has no symbols (stripped?)\n");
        set_load_error(info, "module has no symbols (stripped?)");
        return -ENOEXEC;
    }
    Elf_Shdr *symbols = &info->sechdrs[info->index.sym];
    if (symbols->sh_size % sizeof(Elf_Sym) || symbols->sh_link >= info->hdr->e_shnum) {
        set_load_error(info, "invalid ELF symbol table");
        return -ENOEXEC;
    }
    Elf_Shdr *strings = &info->sechdrs[symbols->sh_link];
    if (strings->sh_type != SHT_STRTAB || !strings->sh_size) {
        set_load_error(info, "invalid ELF symbol strings");
        return -ENOEXEC;
    }
    Elf_Sym *table = (void *)info->hdr + symbols->sh_offset;
    for (unsigned int i = 0; i < symbols->sh_size / sizeof(Elf_Sym); i++) {
        if (table[i].st_name >= strings->sh_size ||
            !memchr(info->strtab + table[i].st_name, 0, strings->sh_size - table[i].st_name)) {
            set_load_error(info, "unterminated ELF symbol name");
            return -ENOEXEC;
        }
    }
    {
        int export_sec = find_sec(info, ".kpm.export");
        if (export_sec && info->sechdrs[export_sec].sh_size % sizeof(struct kpm_export_entry)) {
            set_load_error(info, "malformed .kpm.export section");
            return -ENOEXEC;
        }
    }
    return 0;
}

static int elf_header_check(struct load_info *info)
{
    if (info->len <= sizeof(*(info->hdr))) {
        set_load_error(info, "ELF header is truncated");
        return -ENOEXEC;
    }
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr)) {
        set_load_error(info, "ELF header is not a supported AArch64 relocatable module");
        return -ENOEXEC;
    }
    if (info->hdr->e_shoff >= info->len || (info->hdr->e_shnum * sizeof(Elf_Shdr) > info->len - info->hdr->e_shoff)) {
        set_load_error(info, "ELF section headers are invalid");
        return -ENOEXEC;
    }
    return 0;
}

struct module modules = { 0 };

long load_module_ex(const void *data, int len, const char *args, const char *event, const char *source,
                    void *__user reserved)
{
    struct load_info load_info = { .len = len, .hdr = data };
    struct load_info *info = &load_info;
    long rc = 0;

    if ((rc = elf_header_check(info))) goto out;
    if ((rc = setup_load_info(info))) goto out;

    rcu_read_lock();
    bool module_exists = find_module(info->info.name) != NULL;
    rcu_read_unlock();
    if (module_exists) {
        logkfd("%s exist\n", info->info.name);
        set_load_error(info, "module already exists");
        rc = -EEXIST;
        goto out;
    }

    struct module *mod = (struct module *)vmalloc(sizeof(struct module));
    if (!mod) {
        set_load_error(info, "allocate module state failed");
        rc = -ENOMEM;
        goto out;
    }
    memset(mod, 0, sizeof(struct module));
    snprintf(mod->load_event, sizeof(mod->load_event), "%s", event ? event : "");
    snprintf(mod->load_source, sizeof(mod->load_source), "%s", source ? source : "embedded");

    if (args) {
        mod->args = vmalloc(strlen(args) + 1);
        if (!mod->args) {
            set_load_error(info, "allocate module args failed");
            rc = -ENOMEM;
            goto free1;
        }
        strcpy(mod->args, args);
    }

    layout_sections(mod, info);
    layout_symtab(mod, info);
    if ((rc = kpm_prepare_link(mod, info))) {
        set_load_error(info, "module link arena too large or invalid");
        goto free;
    }

    if ((rc = move_module(mod, info))) {
        set_load_error(info, "allocate executable module memory failed");
        goto free;
    }
    if ((rc = simplify_symbols(mod, info))) goto free;
    if ((rc = apply_relocations(mod, info))) {
        set_load_error(info, "apply relocations failed");
        goto free;
    }

    flush_icache_all();

    rc = (*mod->init)(mod->args, event, reserved);

    if (!rc) {
        logkfi("[%s] initialized\n", mod->info.name);
        {
            unsigned long flags;
            bool duplicate;
            rcu_read_lock();
            flags = kp_private_spin_lock(&module_lock);
            duplicate = find_module(mod->info.name) != NULL;
            if (!duplicate)
                list_add_tail_rcu(&mod->list, &modules.list);
            kp_private_spin_unlock(&module_lock, flags);
            rcu_read_unlock();
            if (duplicate) {
                set_load_error(info, "module already exists");
                rc = -EEXIST;
                (*mod->exit)(reserved);
                goto free;
            }
        }
        goto out;
    } else {
        set_load_error(info, "module init failed");
        logkfi("[%s] init failed: %ld, try exit ...\n", mod->info.name, rc);
        (*mod->exit)(reserved);
    }

free:
    /* A failed load must undo the dependency references it took, exactly like
     * the kernel module loader when init_module fails. */
    {
        unsigned int i;
        unsigned long flags = kp_private_spin_lock(&module_lock);
        for (i = 0; i < mod->dep_count; i++) mod->deps[i]->export_refs--;
        mod->dep_count = 0;
        kp_private_spin_unlock(&module_lock, flags);
    }
    if (mod->args) kvfree(mod->args);
    kp_free_exec(mod->start);
free1:
    kvfree(mod);
out:
    set_kpm_load_result(reserved, rc, rc ? load_error(info, "load module failed") : "module loaded");
    return rc;
}

// todo: lock
long unload_module(const char *name, void *__user reserved)
{
    struct module *mod;
    unsigned long lock_flags;
    unsigned int i;
    long rc;

    if (!name) return -EINVAL;
    if (!kfunc(synchronize_rcu)) return -ENOSYS;
    logkfe("name: %s\n", name);

    rcu_read_lock();
    lock_flags = kp_private_spin_lock(&module_lock);
    mod = find_module(name);
    if (!mod) {
        kp_private_spin_unlock(&module_lock, lock_flags);
        rcu_read_unlock();
        return -ENOENT;
    }
    if (mod->export_refs) {
        logkfe("module %s is in use by %u other KPM(s)\n", name, mod->export_refs);
        kp_private_spin_unlock(&module_lock, lock_flags);
        rcu_read_unlock();
        return -EBUSY;
    }
    list_del_rcu(&mod->list);
    kp_private_spin_unlock(&module_lock, lock_flags);
    rcu_read_unlock();

    kfunc(synchronize_rcu)();
    rc = (*mod->exit)(reserved);

    lock_flags = kp_private_spin_lock(&module_lock);
    for (i = 0; i < mod->dep_count; i++) mod->deps[i]->export_refs--;
    mod->dep_count = 0;
    kp_private_spin_unlock(&module_lock, lock_flags);

    if (mod->args) kvfree(mod->args);
    if (mod->ctl_args) kvfree(mod->ctl_args);
    kp_free_exec(mod->start);
    kvfree(mod);
    logkfi("name: %s, rc: %ld\n", name, rc);
    return rc;
}

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved)
{
    return load_module_ex(data, len, args, event, "embedded", reserved);
}

long load_module_path_event(const char *path, const char *args, const char *event, void *__user reserved)
{
    long rc = 0;
    logkfd("%s\n", path);
    if (!path) {
        rc = -EINVAL;
        set_kpm_load_result(reserved, rc, "module path is null");
        return rc;
    }

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (unlikely(!filp || IS_ERR(filp))) {
        logkfe("open module: %s error\n", path);
        rc = PTR_ERR(filp);
        set_kpm_load_result(reserved, rc, "open module file failed");
        goto out;
    }
    loff_t len = vfs_llseek(filp, 0, SEEK_END);
    if (len <= 0 || len > KPM_LINK_MAX_IMAGE) {
        rc = len < 0 ? len : -E2BIG;
        set_kpm_load_result(reserved, rc, "module file size invalid or too large");
        goto close;
    }
    logkfd("module size: %llx\n", len);
    vfs_llseek(filp, 0, SEEK_SET);

    void *data = vmalloc(len);
    if (!data) {
        rc = -ENOMEM;
        set_kpm_load_result(reserved, rc, "allocate module file buffer failed");
        goto close;
    }
    memset(data, 0, len);

    loff_t pos = 0;
    kernel_read(filp, data, len, &pos);
    filp_close(filp, 0);
    filp = 0;

    if (pos != len) {
        logkfe("read module: %s error\n", path);
        rc = -EIO;
        set_kpm_load_result(reserved, rc, "read module file failed");
        goto free;
    }

    rc = load_module_ex(data, len, args, event ? event : "load-file", "file", reserved);
free:
    kvfree(data);
close:
    if (filp) filp_close(filp, 0);
out:
    return rc;
}

long load_module_path(const char *path, const char *args, void *__user reserved)
{
    return load_module_path_event(path, args, "load-file", reserved);
}

long module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen)
{
    if (!name || !ctl_args) return -EINVAL;
    int args_len = strlen(ctl_args);
    if (args_len <= 0) return -EINVAL;

    logkfi("control module: %s\n", name);

    long rc = 0;
    rcu_read_lock();

    struct module *mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }

    if (!mod->ctl0 || !*mod->ctl0) {
        logkfe("no ctl0\n");
        rc = -ENOSYS;
        goto out;
    }

    if (mod->ctl_args) kvfree(mod->ctl_args);

    mod->ctl_args = vmalloc(args_len + 1);
    if (!mod->ctl_args) {
        rc = -ENOMEM;
        goto out;
    }

    strcpy(mod->ctl_args, ctl_args);

    rc = (*mod->ctl0)(mod->ctl_args, out_msg, outlen);

    logkfi("name: %s, rc: %d\n", name, rc);
out:
    rcu_read_unlock();
    return rc;
}

long module_control1(const char *name, void *a1, void *a2, void *a3)
{
    logkfi("name %s, a1: %llx, a2: %llx, a3: %llx\n", name, a1, a2, a3);
    long rc = 0;
    rcu_read_lock();

    struct module *mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }

    if (!mod->ctl1 || !*mod->ctl1) {
        logkfe("no ctl1\n");
        rc = -ENOSYS;
        goto out;
    }

    rc = (*mod->ctl1)(a1, a2, a3);

    logkfi("name: %s, rc: %d\n", name, rc);
out:
    rcu_read_unlock();
    return rc;
}

long notify_modules_event(const char *event, const char *args, void *__user reserved)
{
    if (!event) return -EINVAL;

    long result = 0;
    int count = 0;
    rcu_read_lock();

    struct module *pos;
    list_for_each_entry_rcu(pos, &modules.list, list)
    {
        if (!pos->event || !*pos->event) continue;

        long rc = (*pos->event)(event, args, reserved);
        logkfi("event: %s, module: %s, rc: %ld\n", event, pos->info.name, rc);
        if (rc < 0 && !result) result = rc;
        count++;
    }

    rcu_read_unlock();
    return result ?: count;
}
KP_EXPORT_SYMBOL(notify_modules_event);

struct module *find_module(const char *name)
{
    struct module *pos;
    list_for_each_entry_rcu(pos, &modules.list, list)
    {
        if (!strcmp(name, pos->info.name)) {
            return pos;
        }
    }
    return 0;
}

int get_module_nums()
{
    rcu_read_lock();

    struct module *pos;
    int n = 0;
    list_for_each_entry_rcu(pos, &modules.list, list)
    {
        n++;
    }
    rcu_read_unlock();

    logkfd("%d\n", n);
    return n;
}

int list_modules(char *out_names, int size)
{
    if (!out_names || size <= 0) return -EINVAL;
    out_names[0] = '\0';

    rcu_read_lock();

    struct module *pos;
    int off = 0;
    list_for_each_entry_rcu(pos, &modules.list, list)
    {
        off += snprintf(out_names + off, size - 1 - off, "%s\n", pos->info.name);
    }
    if (off > 0) out_names[off - 1] = '\0';

    rcu_read_unlock();
    return off;
}

int get_module_info(const char *name, char *out_info, int size)
{
    if (size <= 0) return 0;
    rcu_read_lock();

    struct module *mod = find_module(name);
    if (!mod) return -ENOENT;

    int sz = snprintf(out_info, size,
                      "name=%s\n"
                      "version=%s\n"
                      "license=%s\n"
                      "author=%s\n"
                      "description=%s\n"
                      "args=%s\n",
                      mod->info.name, mod->info.version, mod->info.license, mod->info.author, mod->info.description,
                      mod->args ? mod->args : "");

    if (sz < 0) sz = 0;
    if (sz < size) {
        int tail = snprintf(out_info + sz, size - sz,
                            "load_event=%s\n"
                            "load_source=%s\n",
                            mod->load_event, mod->load_source);
        if (tail > 0) sz += tail;
    }

    out_info[size - 1] = '\0';
    logkfd("%s", out_info);

    rcu_read_unlock();
    return sz;
}

void module_init()
{
    INIT_LIST_HEAD(&modules.list);
    spin_lock_init(&module_lock);
}
