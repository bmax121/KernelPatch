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
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>

#include "../include/kp_lkm.h"

#define SZ_128M 0x08000000

#define ARCH_SHF_SMALL 0

/* Runtime-resolved kernel symbols (not exported on GKI 5.15). */
static void *(*kp_module_alloc)(unsigned long size);
static void (*kp_module_memfree)(void *module_region);
static void (*kp_flush_icache_all_fn)(void);

/* Runtime-resolved kernel functions and raw KPM callbacks cannot participate
 * in this LKM's CFI jump table. Keep CFI enabled everywhere else and exempt
 * only these indirect-call boundaries. */
__attribute__((no_sanitize("cfi")))
static void *kp_malloc_exec(unsigned long size)
{
	return kp_module_alloc(size);
}

__attribute__((no_sanitize("cfi")))
static void kp_free_exec(void *region)
{
	kp_module_memfree(region);
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

	if (!kp_module_alloc || !kp_module_memfree) {
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

	kp_flush_kpm_icache(mod->start, mod->size);
	logkfe("KPM [%s] icache flushed\n", info->info.name);

	pr_emerg(KPLKM_TAG ": KPM [%s] entering init=%px image=%px size=%u\n",
		 mod->info.name, mod->init, mod->start, mod->size);
	/* dump first 4 instructions of the relocated init to verify the copy */
	{
		u32 *ip = (u32 *)mod->init;
		pr_emerg(KPLKM_TAG ": KPM [%s] init insn: %08x %08x %08x %08x\n",
			 mod->info.name, ip[0], ip[1], ip[2], ip[3]);
	}
	rc = kp_call_init(mod->init, mod->args, event, reserved);
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

	/* module_alloc/module_memfree are not exported to modules on GKI, but
	 * they exist in kallsyms (kernel/module.c, non-static). Resolve them at
	 * runtime; module_alloc gives PAGE_KERNEL_EXEC memory in the module
	 * region, which is what a freshly-relocated KPM needs. */
	kp_module_alloc = (void *(*)(unsigned long))kallsyms_lookup_name("module_alloc");
	kp_module_memfree = (void (*)(void *))kallsyms_lookup_name("module_memfree");
	kp_flush_icache_all_fn = (void (*)(void))kallsyms_lookup_name("flush_icache_all");

	if (!kp_module_alloc || !kp_module_memfree) {
		logke("module_alloc/module_memfree not resolvable; KPM loading disabled\n");
		return -ENOSYS;
	}
	logki("kpm loader ready (module_alloc=%px flush_icache_all=%px)\n", kp_module_alloc,
	      kp_flush_icache_all_fn);
	return 0;
}
