// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KernelPatch Module (KPM) loader for the LKM framework. Ported from
 * kernel/patch/module/module.c. The KPM is a relocatable ELF; undefined
 * symbols resolve against the running kernel via kallsyms (KP uses its own
 * symbol_lookup_name there). Executable memory comes from module_alloc()
 * (module_memfree() to release), both resolved at runtime since they are not
 * exported to modules on GKI.
 */
#include "module.h"
#include "relo.h"
#include "symbols.h"

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include "../include/kp_lkm.h"

#define SZ_128M 0x08000000

#define ARCH_SHF_SMALL 0

/* arm64 PTE permission bits. PXN (bit53) / UXN (bit54) gate execution;
 * GP (bit50) enables BTI. KPM pages must have them all clear. */
#ifndef PTE_PXN
#define KP_LKM_PTE_PXN (1UL << 53)
#define KP_LKM_PTE_UXN (1UL << 54)
#define KP_LKM_PTE_GP  (1UL << 50)
#else
#define KP_LKM_PTE_PXN PTE_PXN
#define KP_LKM_PTE_UXN PTE_UXN
#define KP_LKM_PTE_GP  PTE_GP
#endif

/* Runtime-resolved kernel symbols (not exported on GKI 5.15). */
static void *(*kp_module_alloc)(unsigned long size);
static void (*kp_module_memfree)(void *module_region);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#include <linux/execmem.h>
static void *(*kp_execmem_alloc)(enum execmem_type type, size_t size);
static void (*kp_execmem_free)(void *ptr);
#else
static void *(*kp_execmem_alloc)(int type, size_t size);
static void (*kp_execmem_free)(void *ptr);
#endif
static void (*kp_flush_icache_all_fn)(void);
static int (*kp_set_memory_x)(unsigned long addr, int numpages);
static int (*kp_set_memory_nx)(unsigned long addr, int numpages);

/* init_mm (resolved at runtime, not exported on GKI). */
static struct mm_struct *kp_kpm_init_mm;

/* Clear the Guarded-Page bit (BTI enable), Privileged-eXecute-Never and
 * User-eXecute-Never for a range of virtual addresses.  KPM code is bare-metal
 * compiled without bti c landing pads, but GKI kernels set PTE_GP on module_alloc
 * pages, and module_alloc may return PXN pages (NX) that set_memory_x() fails to
 * flip on some builds.  Clearing PXN/UXN makes the image executable and clearing
 * GP disables BTI so every indirect call (BLR) from KPM code works. */
static void kp_clear_bti_gp(unsigned long base, unsigned long size)
{
	unsigned long addr, end;

	if (!kp_kpm_init_mm)
		return;

	end = base + size;
	for (addr = base; addr < end; addr += PAGE_SIZE) {
		pgd_t *pgd = pgd_offset(kp_kpm_init_mm, addr);
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		if (pgd_none(*pgd) || pgd_bad(*pgd))
			continue;
		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d) || p4d_bad(*p4d))
			continue;
		pud = pud_offset(p4d, addr);
		if (pud_none(*pud) || pud_bad(*pud))
			continue;
		if (pud_sect(*pud))
			continue; /* huge page, skip — KPM pages are 4K */
		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			continue;
		if (pmd_sect(*pmd))
			continue;
		pte = pte_offset_kernel(pmd, addr);
		if (!pte || !pte_present(*pte))
			continue;

		pteval_t v = pte_val(*pte);
		if (v & (KP_LKM_PTE_PXN | KP_LKM_PTE_UXN | KP_LKM_PTE_GP)) {
			v &= ~(KP_LKM_PTE_PXN | KP_LKM_PTE_UXN | KP_LKM_PTE_GP);
			set_pte(pte, __pte(v));
			flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
		}
	}
}

/* Runtime-resolved kernel functions and raw KPM callbacks cannot participate
 * in this LKM's CFI jump table. Keep CFI enabled everywhere else and exempt
 * only these indirect-call boundaries. noinline: if inlined into a
 * CFI-instrumented caller, the kCFI type-hash load of [fnptr - 4] dereferences
 * NULL when the allocator is absent (6.10+ has no module_alloc). */
__attribute__((no_sanitize("cfi"), __noinline__))
static void *kp_malloc_exec(unsigned long size)
{
	if (kp_module_alloc)
		return kp_module_alloc(size);
	if (kp_execmem_alloc)
		return kp_execmem_alloc(0 /* EXECMEM_MODULE_TEXT */, size);
	return vmalloc(size);
}

__attribute__((no_sanitize("cfi"), __noinline__))
static void kp_free_exec(void *region)
{
	if (kp_module_memfree)
		kp_module_memfree(region);
	else if (kp_execmem_free)
		kp_execmem_free(region);
	else
		vfree(region);
}

__attribute__((no_sanitize("cfi")))
static void kp_flush_kpm_icache(void *start, size_t size)
{
	(void)start; (void)size; (void)kp_flush_icache_all_fn;
	dsb(ishst);
	asm volatile("ic iallu");
	dsb(ish);
	isb();
}

__attribute__((no_sanitize("cfi")))
static long kp_call_init(mod_initcall_t *fn, const char *args, const char *event,
			 void __user *reserved)
{
	return (*fn)(args, event, reserved);
}

__attribute__((no_sanitize("cfi")))
static long kp_call_exit(mod_exitcall_t *fn, void __user *reserved)
{
	return (*fn)(reserved);
}

__attribute__((no_sanitize("cfi")))
static int kp_do_set_memory_x(unsigned long addr, int npages)
{
	return kp_set_memory_x(addr, npages);
}

__attribute__((no_sanitize("cfi")))
static int kp_do_set_memory_nx(unsigned long addr, int npages)
{
	return kp_set_memory_nx(addr, npages);
}

__attribute__((no_sanitize("cfi")))
static long kp_call_ctl0(mod_ctl0call_t *fn, const char *args, char __user *out, int outlen)
{
	return (*fn)(args, out, outlen);
}

__attribute__((no_sanitize("cfi")))
static long kp_call_ctl1(mod_ctl1call_t *fn, void *a1, void *a2, void *a3)
{
	return (*fn)(a1, a2, a3);
}

__attribute__((no_sanitize("cfi")))
static long kp_call_event(mod_eventcall_t *fn, const char *event, const char *args,
			  void __user *reserved)
{
	return (*fn)(event, args, reserved);
}

static void set_load_error(struct kp_load_info *info, const char *message)
{
	if (!info || !message)
		return;
	snprintf(info->info.error_msg, sizeof(info->info.error_msg), "%s", message);
}

static const char *load_error(const struct kp_load_info *info, const char *fallback)
{
	if (info && info->info.error_msg[0])
		return info->info.error_msg;
	return fallback;
}

static bool kpm_load_result_enabled(void __user *reserved)
{
	if (!reserved)
		return false;

	struct kpm_load_result *result = memdup_user(reserved, sizeof(*result));
	if (IS_ERR(result))
		return false;

	bool enabled = result->magic == KPM_LOAD_RESULT_MAGIC && result->size >= sizeof(*result);
	kvfree(result);
	return enabled;
}

static void set_kpm_load_result(void __user *reserved, long code, const char *message)
{
	if (!kpm_load_result_enabled(reserved))
		return;

	struct kpm_load_result result;
	memset(&result, 0, sizeof(result));
	result.magic = KPM_LOAD_RESULT_MAGIC;
	result.size = sizeof(result);
	result.code = code;
	if (message)
		snprintf(result.message, sizeof(result.message), "%s", message);
	if (copy_to_user(reserved, &result, sizeof(result)))
		logkd("kpm load result: copy_to_user failed\n");
}

static char *next_string(char *string, unsigned long *secsize)
{
	while (string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return 0;
	}
	while (!string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return 0;
	}
	return string;
}

/* Update size with this section: return offset. */
static long get_offset(struct kp_module *mod, unsigned int *size, Elf_Shdr *sechdr,
		       unsigned int section)
{
	long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
	*size = ret + sechdr->sh_size;
	return ret;
}

static char *get_next_modinfo(const struct kp_load_info *info, const char *tag, char *prev)
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
		if (strncmp(p, tag, taglen) == 0 && p[taglen] == '=')
			return p + taglen + 1;
	}
	return 0;
}

static char *get_modinfo(const struct kp_load_info *info, const char *tag)
{
	return get_next_modinfo(info, tag, 0);
}

static int find_sec(const struct kp_load_info *info, const char *name)
{
	for (int i = 1; i < info->hdr->e_shnum; i++) {
		Elf_Shdr *shdr = &info->sechdrs[i];
		if ((shdr->sh_flags & SHF_ALLOC) && strcmp(info->secstrings + shdr->sh_name, name) == 0)
			return i;
	}
	return 0;
}

static void *get_sh_base(struct kp_load_info *info, const char *secname)
{
	int idx = find_sec(info, secname);
	if (!idx)
		return 0;
	Elf_Shdr *infosec = &info->sechdrs[idx];
	void *addr = (void *)info->hdr + infosec->sh_offset;
	return addr;
}

static unsigned long get_sh_size(struct kp_load_info *info, const char *secname)
{
	int idx = find_sec(info, secname);
	if (!idx)
		return 0;
	Elf_Shdr *infosec = &info->sechdrs[idx];
	return infosec->sh_entsize;
}

static void layout_sections(struct kp_module *mod, struct kp_load_info *info)
{
	static unsigned long const masks[][2] = {
		/* executable code must be first; text_size finder relies on it */
		{ SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
		{ SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
		{ SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
		{ ARCH_SHF_SMALL | SHF_ALLOC, 0 },
	};

	for (int i = 0; i < info->hdr->e_shnum; i++)
		info->sechdrs[i].sh_entsize = ~0UL;

	for (int m = 0; m < (int)(sizeof(masks) / sizeof(masks[0])); ++m) {
		for (int i = 0; i < info->hdr->e_shnum; ++i) {
			Elf_Shdr *s = &info->sechdrs[i];
			if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) ||
			    s->sh_entsize != ~0UL)
				continue;
			s->sh_entsize = get_offset(mod, &mod->size, s, i);
		}
		switch (m) {
		case 0: /* executable */
			mod->size = ALIGN(mod->size, PAGE_SIZE);
			mod->text_size = mod->size;
			break;
		case 1: /* RO: text and ro-data */
			mod->size = ALIGN(mod->size, PAGE_SIZE);
			mod->ro_size = mod->size;
			break;
		case 2:
			break;
		case 3: /* whole */
			mod->size = ALIGN(mod->size, PAGE_SIZE);
			break;
		}
	}
}

static bool is_core_symbol(const Elf_Sym *src, const Elf_Shdr *sechdrs, unsigned int shnum)
{
	const Elf_Shdr *sec;
	if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name)
		return false;
	sec = sechdrs + src->st_shndx;
	if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR))
		return false;
	return true;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(struct kp_module *mod, struct kp_load_info *info)
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
			if (!strncmp(name, "__gnu_lto", 9)) {
				logkd("Please compile with -fno-common\n");
				ret = -ENOEXEC;
			}
			break;
		case SHN_ABS:
			break;
		case SHN_UNDEF:
		{
			unsigned long addr = kp_kpm_symbol_lookup(name);
			if (!addr)
				addr = kallsyms_lookup_name(name);
			if (!addr) {
				logke("unknown symbol: %s\n", name);
				if (!info->info.error_msg[0])
					snprintf(info->info.error_msg, sizeof(info->info.error_msg),
						 "unknown symbol: %s", name);
				ret = -ENOENT;
				break;
			}
			sym[i].st_value = addr;
			break;
		}
		default:
			secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
			sym[i].st_value += secbase;
			break;
		}
	}
	return ret;
}

static int apply_relocations(struct kp_module *mod, const struct kp_load_info *info)
{
	int rc = 0;
	unsigned int i;
	for (i = 1; i < info->hdr->e_shnum; i++) {
		unsigned int infosec = info->sechdrs[i].sh_info;
		if (infosec >= info->hdr->e_shnum)
			continue;
		if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC))
			continue;
		if (info->sechdrs[i].sh_type == SHT_REL) {
			rc = kp_apply_relocate(info->sechdrs, info->strtab, info->index.sym, i, mod);
		} else if (info->sechdrs[i].sh_type == SHT_RELA) {
			rc = kp_apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
		}
		if (rc < 0)
			break;
	}
	return rc;
}

static void layout_symtab(struct kp_module *mod, struct kp_load_info *info)
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

static int rewrite_section_headers(struct kp_load_info *info)
{
	info->sechdrs[0].sh_addr = 0;
	for (int i = 1; i < info->hdr->e_shnum; i++) {
		Elf_Shdr *shdr = &info->sechdrs[i];
		if (shdr->sh_type != SHT_NOBITS && info->len < shdr->sh_offset + shdr->sh_size)
			return -ENOEXEC;
		/* Mark all sections sh_addr with their address in the temporary image. */
		shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
	}
	return 0;
}

static int move_module(struct kp_module *mod, struct kp_load_info *info)
{
	logki("kpm alloc module size: %x\n", mod->size);
	mod->start = kp_malloc_exec(mod->size);
	if (!mod->start)
		return -ENOMEM;
	memset(mod->start, 0, mod->size);

	for (int i = 1; i < info->hdr->e_shnum; i++) {
		void *dest;
		Elf_Shdr *shdr = &info->sechdrs[i];
		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		dest = mod->start + shdr->sh_entsize;
		const char *sname = info->secstrings + shdr->sh_name;

		if (shdr->sh_type != SHT_NOBITS)
			memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

		shdr->sh_addr = (unsigned long)dest;

		if (!mod->init && !strcmp(".kpm.init", sname))
			mod->init = (mod_initcall_t *)dest;
		if (!strcmp(".kpm.ctl0", sname))
			mod->ctl0 = (mod_ctl0call_t *)dest;
		if (!strcmp(".kpm.ctl1", sname))
			mod->ctl1 = (mod_ctl1call_t *)dest;
		if (!mod->exit && !strcmp(".kpm.exit", sname))
			mod->exit = (mod_exitcall_t *)dest;
		if (!mod->event && !strcmp(".kpm.event", sname))
			mod->event = (mod_eventcall_t *)dest;
		if (!mod->info.base && !strcmp(".kpm.info", sname))
			mod->info.base = (const char *)dest;
	}
	mod->info.name = info->info.name - info->info.base + mod->info.base;
	mod->info.version = info->info.version - info->info.base + mod->info.base;

	if (info->info.license)
		mod->info.license = info->info.license - info->info.base + mod->info.base;
	if (info->info.author)
		mod->info.author = info->info.author - info->info.base + mod->info.base;
	if (info->info.description)
		mod->info.description = info->info.description - info->info.base + mod->info.base;

	return 0;
}

static int setup_load_info(struct kp_load_info *info)
{
	int rc = 0;
	info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
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
	logkd("loading module:\n");
	logkd("    name: %s\n", name);

	const char *version = get_modinfo(info, "version");
	if (!version) {
		logkd("module version not found\n");
		set_load_error(info, "module version not found");
		return -ENOEXEC;
	}
	info->info.version = version;
	logkd("    version: %s\n", version);

	info->info.license = get_modinfo(info, "license");
	info->info.author = get_modinfo(info, "author");
	info->info.description = get_modinfo(info, "description");

	for (int i = 1; i < info->hdr->e_shnum; i++) {
		if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
			info->index.sym = i;
			info->index.str = info->sechdrs[i].sh_link;
			info->strtab = (char *)info->hdr + info->sechdrs[info->index.str].sh_offset;
			break;
		}
	}

	if (info->index.sym == 0) {
		logkd("module has no symbols (stripped?)\n");
		set_load_error(info, "module has no symbols (stripped?)");
		return -ENOEXEC;
	}
	return 0;
}

static int elf_header_check(struct kp_load_info *info)
{
	if (info->len <= sizeof(*(info->hdr))) {
		set_load_error(info, "ELF header is truncated");
		return -ENOEXEC;
	}
	if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL ||
	    info->hdr->e_machine != EM_AARCH64 || info->hdr->e_shentsize != sizeof(Elf_Shdr)) {
		set_load_error(info, "ELF header is not a supported AArch64 relocatable module");
		return -ENOEXEC;
	}
	if (info->hdr->e_shoff >= info->len ||
	    (info->hdr->e_shnum * sizeof(Elf_Shdr) > info->len - info->hdr->e_shoff)) {
		set_load_error(info, "ELF section headers are invalid");
		return -ENOEXEC;
	}
	return 0;
}

struct kp_module modules = { 0 };
static spinlock_t module_lock;

/* Set while a KPM's init runs: during that window the module is not yet on
 * modules.list, but its image must already be shielded from the Qualcomm
 * find_check_fn() panic / BTI faults (the KPM may iterate kallsyms from init).
 * Cleared as soon as kp_call_init() returns. */
static struct kp_module *kp_loading_mod;

/* One PAGE_SIZE module_alloc'd RWX page. The safe kallsyms_on_each_symbol()
 * stand-in bounces KPM callbacks through an 8-byte bti-c trampoline at
 * page+8 so the kernel's BLR lands on a guarded landing pad instead of the
 * bare-metal (non-BTI) KPM code. Bytes page+0..+7 are kept zeroed so the
 * KCFI inline check's [target-4] read stays inside the mapped page. */
static void *kp_callback_tramp;
static unsigned long kp_callback_tramp_size;

typedef int (*kp_kallsyms_on_each_symbol_t)(kp_kallsyms_cb_t fn, void *data);
static kp_kallsyms_on_each_symbol_t kp_real_kallsyms_on_each_symbol;

static bool kp_kpm_ready; /* modules.list / module_lock / trampoline initialized */

/* Address-in-KPM-range check used by the find_check_fn CFI bypass and by the
 * safe kallsyms wrapper. Callable from any (including atomic) context. */
bool kp_kpm_cfi_allowed_addr(unsigned long addr)
{
	struct kp_module *pos;
	unsigned long start, end;
	bool ok = false;

	if (!READ_ONCE(kp_kpm_ready))
		return false;

	rcu_read_lock();
	list_for_each_entry(pos, &modules.list, list) {
		start = (unsigned long)pos->start;
		end = start + pos->size;
		if (addr >= start && addr < end) {
			ok = true;
			break;
		}
	}
	rcu_read_unlock();
	if (ok)
		return true;

	/* The module being initialized is not linked yet. */
	{
		struct kp_module *loading = READ_ONCE(kp_loading_mod);
		if (loading) {
			start = (unsigned long)loading->start;
			end = start + loading->size;
			if (addr >= start && addr < end)
				return true;
		}
	}

	if (kp_callback_tramp) {
		start = (unsigned long)kp_callback_tramp;
		end = start + kp_callback_tramp_size;
		if (addr >= start && addr < end)
			return true;
	}
	return false;
}

/* The kernel's own kallsyms_on_each_symbol() is exported to KPMs through a
 * function-pointer slot in the LKM (see symbols.c). We install this stand-in
 * instead: for a KPM callback it writes a "bti c; b <fn>" trampoline into the
 * RWX trampoline page and hands the trampoline address to the real kernel
 * iterator. find_check_fn() then validates the trampoline page (covered by
 * kp_kpm_cfi_allowed_addr, noop check fn) and the BLR lands on bti c, which
 * direct-branches into the non-BTI KPM callback with the call args intact. */
__attribute__((no_sanitize("cfi")))
int kp_kpm_safe_kallsyms_on_each_symbol(kp_kallsyms_cb_t fn, void *data)
{
	if (!kp_real_kallsyms_on_each_symbol)
		return -EOPNOTSUPP;

	if (!kp_callback_tramp || !kp_kpm_cfi_allowed_addr((unsigned long)fn))
		return kp_real_kallsyms_on_each_symbol(fn, data);

	{
		unsigned long flags;
		u32 *slot = (u32 *)kp_callback_tramp + 2; /* page+8 */
		u32 *pad = (u32 *)kp_callback_tramp;
		long off = (long)((unsigned long)fn - ((unsigned long)slot + 4));

		pr_emerg(KPLKM_TAG ": kallsyms safe: fn=%px tramp=%px off=%ld\n",
			 (void *)fn, kp_callback_tramp, off);

		spin_lock_irqsave(&module_lock, flags);
		pad[0] = 0; /* keep [target-4] mapped + zeroed for the KCFI check */
		pad[1] = 0;
		slot[0] = 0xd503245f; /* bti c */
		slot[1] = 0x14000000 | (((unsigned long)off >> 2) & 0x03ffffff); /* b <fn> */
		dsb(ishst);
		asm volatile("ic iallu");
		dsb(ish);
		isb();
		spin_unlock_irqrestore(&module_lock, flags);
	}

	{
		int r = kp_real_kallsyms_on_each_symbol((kp_kallsyms_cb_t)((char *)kp_callback_tramp + 8), data);
		pr_emerg(KPLKM_TAG ": kallsyms safe done rc=%d\n", r);
		return r;
	}
}

static struct kp_module *kp_find_module(const char *name)
{
	struct kp_module *pos;
	list_for_each_entry(pos, &modules.list, list)
	{
		if (!strcmp(name, pos->info.name))
			return pos;
	}
	return 0;
}

long kp_load_module(const void *data, int len, const char *args, const char *event,
		    void __user *reserved)
{
	struct kp_load_info load_info = { .len = len, .hdr = data };
	struct kp_load_info *info = &load_info;
	long rc = 0;

	if (!kp_module_alloc && !kp_execmem_alloc) {
		set_load_error(info, "executable memory allocator unavailable");
		rc = -ENOSYS;
		goto out;
	}

	if ((rc = elf_header_check(info)))
		goto out;
	if ((rc = setup_load_info(info)))
		goto out;

	if (kp_find_module(info->info.name)) {
		logkfd("%s exist\n", info->info.name);
		set_load_error(info, "module already exists");
		rc = -EEXIST;
		goto out;
	}

	struct kp_module *mod = (struct kp_module *)kzalloc(sizeof(struct kp_module), GFP_KERNEL);
	if (!mod) {
		set_load_error(info, "allocate module state failed");
		rc = -ENOMEM;
		goto out;
	}

	if (args) {
		mod->args = kstrdup(args, GFP_KERNEL);
		if (!mod->args) {
			set_load_error(info, "allocate module args failed");
			rc = -ENOMEM;
			goto free1;
		}
	}

	layout_sections(mod, info);
	layout_symtab(mod, info);
	logkfe("KPM [%s] layout done size=0x%x\n", info->info.name, mod->size);

	if ((rc = move_module(mod, info))) {
		set_load_error(info, "allocate executable module memory failed");
		goto free;
	}
	logkfe("KPM [%s] moved to %px init=%px\n", info->info.name, mod->start, mod->init);
	if ((rc = simplify_symbols(mod, info)))
		goto free;
	logkfe("KPM [%s] symbols resolved\n", info->info.name);
	if ((rc = apply_relocations(mod, info))) {
		set_load_error(info, "apply relocations failed");
		goto free;
	}
	logkfe("KPM [%s] relocations applied\n", info->info.name);

	/* GKI 5.10+ module_alloc returns PAGE_KERNEL (PXN set, non-executable).
	 * The kernel's own module loader calls set_memory_x() after writing; we
	 * must do the same, otherwise kp_call_init triggers a permission fault. */
	if (kp_set_memory_x) {
		
		int npages = (mod->size + PAGE_SIZE - 1) >> PAGE_SHIFT;
		int xret = kp_do_set_memory_x((unsigned long)mod->start, npages);
		if (xret)
			logke("KPM [%s] set_memory_x(%px, %d) = %d\n",
			      info->info.name, mod->start, npages, xret);
	}

	/* Disable BTI on the KPM pages: the module is bare-metal compiled
		 * without bti c landing pads, and every BLR from KPM code to the
		 * LKM / kernel faults on GKI BTI-enabled kernels. */
		kp_clear_bti_gp((unsigned long)mod->start, mod->size);
	kp_flush_kpm_icache(mod->start, mod->size);
	logkfe("KPM [%s] icache flushed\n", info->info.name);

	pr_emerg(KPLKM_TAG ": KPM [%s] entering init=%px image=%px size=%u\n",
		 mod->info.name, mod->init, mod->start, mod->size);

	WRITE_ONCE(kp_loading_mod, mod);
	pr_emerg(KPLKM_TAG ": KPM [%s] call init fn=%px (*fn)=%px args=%px args0='%s' event='%s'\n",
		 mod->info.name, mod->init,
		 mod->init ? *(mod_initcall_t *)mod->init : 0,
		 mod->args, mod->args ? mod->args : "(null)",
		 event ? event : "(null)");
	rc = kp_call_init(mod->init, mod->args, event, reserved);
	WRITE_ONCE(kp_loading_mod, NULL);
	pr_emerg(KPLKM_TAG ": KPM [%s] init returned %ld\n", mod->info.name, rc);

	if (!rc) {
		logkfi("[%s] succeed with [%s]\n", mod->info.name, args ? args : "");
		list_add_tail(&mod->list, &modules.list);
		goto out;
	} else {
		set_load_error(info, "module init failed");
		logkfi("[%s] failed with [%s] error: %ld, try exit ...\n", mod->info.name,
		       args ? args : "", rc);
		if (mod->exit)
			kp_call_exit(mod->exit, reserved);
	}

free:
	if (mod->args)
		kvfree(mod->args);
	if (mod->start)
		kp_free_exec(mod->start);
free1:
	kfree(mod);
out:
	set_kpm_load_result(reserved, rc, rc ? load_error(info, "load module failed") : "module loaded");
	return rc;
}

long kp_unload_module(const char *name, void __user *reserved)
{
	if (!name)
		return -EINVAL;
	logkfe("name: %s\n", name);

	rcu_read_lock();
	long rc = 0;

	struct kp_module *mod = kp_find_module(name);
	if (!mod) {
		rc = -ENOENT;
		goto out;
	}
	list_del(&mod->list);
	rc = kp_call_exit(mod->exit, reserved);

	if (mod->args)
		kvfree(mod->args);
	if (mod->ctl_args)
		kvfree(mod->ctl_args);

	if (kp_set_memory_nx && mod->start) {
		int npages = (mod->size + PAGE_SIZE - 1) >> PAGE_SHIFT;
		kp_do_set_memory_nx((unsigned long)mod->start, npages);
	}

	if (kp_module_memfree && mod->start)
		kp_free_exec(mod->start);
	kfree(mod);

	logkfi("name: %s, rc: %ld\n", name, rc);

out:
	rcu_read_unlock();
	return rc;
}

long kp_load_module_path(const char *path, const char *args, void __user *reserved)
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

	rc = kp_load_module(data, len, args, "load-file", reserved);
free:
	kvfree(data);
close:
	if (filp)
		filp_close(filp, 0);
out:
	return rc;
}

long kp_module_control0(const char *name, const char *ctl_args, char __user *out_msg, int outlen)
{
	if (!name || !ctl_args)
		return -EINVAL;
	int args_len = strlen(ctl_args);
	if (args_len <= 0)
		return -EINVAL;

	logkfi("name %s, args: %s\n", name, ctl_args);

	long rc = 0;
	rcu_read_lock();

	struct kp_module *mod = kp_find_module(name);
	if (!mod) {
		rc = -ENOENT;
		goto out;
	}

	if (!mod->ctl0 || !*mod->ctl0) {
		logkfe("no ctl0\n");
		rc = -ENOSYS;
		goto out;
	}

	if (mod->ctl_args)
		kvfree(mod->ctl_args);

	mod->ctl_args = kstrdup(ctl_args, GFP_KERNEL);
	if (!mod->ctl_args) {
		rc = -ENOMEM;
		goto out;
	}

	rc = kp_call_ctl0(mod->ctl0, mod->ctl_args, out_msg, outlen);

	logkfi("name: %s, rc: %ld\n", name, rc);
out:
	rcu_read_unlock();
	return rc;
}

long kp_module_control1(const char *name, void *a1, void *a2, void *a3)
{
	logkfi("name %s, a1: %px, a2: %px, a3: %px\n", name, a1, a2, a3);
	long rc = 0;
	rcu_read_lock();

	struct kp_module *mod = kp_find_module(name);
	if (!mod) {
		rc = -ENOENT;
		goto out;
	}

	if (!mod->ctl1 || !*mod->ctl1) {
		logkfe("no ctl1\n");
		rc = -ENOSYS;
		goto out;
	}

	rc = kp_call_ctl1(mod->ctl1, a1, a2, a3);

	logkfi("name: %s, rc: %ld\n", name, rc);
out:
	rcu_read_unlock();
	return rc;
}

long kp_notify_modules_event(const char *event, const char *args, void __user *reserved)
{
	if (!event)
		return -EINVAL;

	long result = 0;
	int count = 0;
	rcu_read_lock();

	struct kp_module *pos;
	list_for_each_entry(pos, &modules.list, list)
	{
		if (!pos->event || !*pos->event)
			continue;

		long rc = kp_call_event(pos->event, event, args, reserved);
		logkfi("event: %s, module: %s, rc: %ld\n", event, pos->info.name, rc);
		if (rc < 0 && !result)
			result = rc;
		count++;
	}

	rcu_read_unlock();
	return result ?: count;
}

int kp_get_module_nums(void)
{
	rcu_read_lock();

	struct kp_module *pos;
	int n = 0;
	list_for_each_entry(pos, &modules.list, list)
	{
		n++;
	}
	rcu_read_unlock();

	logkfd("%d\n", n);
	return n;
}

int kp_list_modules(char *out_names, int size)
{
	if (!out_names || size <= 0)
		return -EINVAL;
	out_names[0] = '\0';

	rcu_read_lock();

	struct kp_module *pos;
	int off = 0;
	list_for_each_entry(pos, &modules.list, list)
	{
		off += snprintf(out_names + off, size - 1 - off, "%s\n", pos->info.name);
	}
	if (off > 0)
		out_names[off - 1] = '\0';

	rcu_read_unlock();
	return off;
}

int kp_get_module_info(const char *name, char *out_info, int size)
{
	if (size <= 0)
		return 0;
	rcu_read_lock();

	struct kp_module *mod = kp_find_module(name);
	if (!mod)
		return -ENOENT;

	int sz = snprintf(out_info, size - 1,
			  "name=%s\n"
			  "version=%s\n"
			  "license=%s\n"
			  "author=%s\n"
			  "description=%s\n"
			  "args=%s\n",
			  mod->info.name, mod->info.version, mod->info.license, mod->info.author,
			  mod->info.description, mod->args ? mod->args : "");

	if (sz > 0)
		out_info[sz - 1] = '\0';
	logkfd("%s", out_info);

	rcu_read_unlock();
	return sz;
}

int kp_kpm_init(void)
{
	INIT_LIST_HEAD(&modules.list);
	spin_lock_init(&module_lock);
	kp_kpm_symbols_init();

	/* module_alloc exists up to ~6.8; 6.10+ replaced it with execmem_alloc
	 * (EXECMEM_MODULE_TEXT). None are exported to modules, but all are in
	 * kallsyms. kp_malloc_exec falls back module_alloc -> execmem_alloc ->
	 * vmalloc. */
	kp_module_alloc = (void *(*)(unsigned long))kallsyms_lookup_name("module_alloc");
	kp_module_memfree = (void (*)(void *))kallsyms_lookup_name("module_memfree");
	kp_execmem_alloc = (void *)kallsyms_lookup_name("execmem_alloc");
	kp_execmem_free = (void *)kallsyms_lookup_name("execmem_free");
	kp_flush_icache_all_fn = (void (*)(void))kallsyms_lookup_name("flush_icache_all");
	kp_set_memory_x = (int (*)(unsigned long, int))kallsyms_lookup_name("set_memory_x");
	kp_set_memory_nx = (int (*)(unsigned long, int))kallsyms_lookup_name("set_memory_nx");
	kp_kpm_init_mm = (struct mm_struct *)kallsyms_lookup_name("init_mm");
	logki("kpm runtime: module_alloc=%px execmem_alloc=%px set_memory_x=%px init_mm=%px\n",
	      kp_module_alloc, kp_execmem_alloc, kp_set_memory_x, kp_kpm_init_mm);

	if (!kp_module_alloc && !kp_execmem_alloc) {
		logke("no module/execmem allocator; KPM loading disabled\n");
		return -ENOSYS;
	}

	/* One RWX page to hold the bti-c trampoline for KPM kallsyms callbacks.
	 * GKI 5.10+ module_alloc returns PAGE_KERNEL (NX), so make it executable
	 * like the KPM images. */
	kp_callback_tramp = kp_malloc_exec(PAGE_SIZE);
	if (kp_callback_tramp) {
		kp_callback_tramp_size = PAGE_SIZE;
		if (kp_set_memory_x) {
			int xret = kp_do_set_memory_x((unsigned long)kp_callback_tramp, 1);
			if (xret)
				logke("callback trampoline set_memory_x(%px) = %d\n",
				      kp_callback_tramp, xret);
		}
		/* module_alloc may return PXN/NX; clear PXN/UXN/GP like KPM images */
		kp_clear_bti_gp((unsigned long)kp_callback_tramp, PAGE_SIZE);
		memset(kp_callback_tramp, 0, PAGE_SIZE);
	} else {
		logkw("callback trampoline alloc failed; KPM kallsyms iteration unshielded\n");
	}

	kp_real_kallsyms_on_each_symbol =
		(kp_kallsyms_on_each_symbol_t)kallsyms_lookup_name("kallsyms_on_each_symbol");
	WRITE_ONCE(kp_kpm_ready, true);

	logki("kpm loader ready (module_alloc=%px flush_icache_all=%px tramp=%px)\n", kp_module_alloc,
	      kp_flush_icache_all_fn, kp_callback_tramp);
	return 0;
}
