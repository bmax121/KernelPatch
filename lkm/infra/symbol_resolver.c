// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Runtime symbol resolver. On GKI kernels kallsyms_lookup_name is exported to
 * modules (the mainline 5.7 de-export was reversed for Android vendor use), so
 * we link it directly and bootstrap everything else by name. kallsyms_on_each_
 * symbol is NOT exported on 5.10; resolve it by name into a function pointer
 * for CFI/llvm-mangled variant matching.
 */
#include "symbol_resolver.h"

#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>

#include "../include/kp_lkm.h"

/* kallsyms_on_each_symbol() dropped the struct module * param from its
 * callback in 6.4; the callback and this fn-pointer type must match the
 * running kernel (kCFI type-hash at the indirect call). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
typedef int (*kp_kallsyms_on_each_symbol_t)(int (*fn)(void *, const char *, unsigned long),
					    void *data);
#else
typedef int (*kp_kallsyms_on_each_symbol_t)(int (*fn)(void *, const char *, struct module *, unsigned long),
					    void *data);
#endif

/* Only meaningful for the name-lookup path below; kallsyms_lookup_name is
 * exported on GKI 5.10 so we call it directly. */
static kp_kallsyms_on_each_symbol_t kp_on_each_symbol;

unsigned long kp_resolve_symbol(const char *name)
{
	return kallsyms_lookup_name(name);
}

struct kp_variant_ctx {
	const char *name;
	size_t name_len;
	unsigned long exact;
	unsigned long variant;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static int kp_variant_cb(void *data, const char *name, unsigned long addr)
#else
static int kp_variant_cb(void *data, const char *name, struct module *m, unsigned long addr)
#endif
{
	struct kp_variant_ctx *ctx = data;
	size_t nlen;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	(void)m;
#endif

	if (!name || !addr)
		return 0;
	nlen = strlen(name);

	if (!strcmp(name, ctx->name)) {
		ctx->exact = addr;
		return 1; /* exact match is always best; stop */
	}
	if (nlen > ctx->name_len && !strncmp(name, ctx->name, ctx->name_len) &&
	    (name[ctx->name_len] == '.' || name[ctx->name_len] == '$')) {
		if (!ctx->variant)
			ctx->variant = addr;
	}
	return 0;
}

void *kp_resolve_symbol_variant(const char *name)
{
	/* Traditional CFI (< 6.1) requires calling functions through their .cfi_jt
	 * canonical-jump-table entry, not the function body — a direct indirect
	 * call to the body trips __cfi_check (panic). Prefer the .cfi_jt variant,
	 * then the exact symbol, then any .llvm.<hash> mangled name. */
	char cfi_name[KSYM_NAME_LEN];
	int n = snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", name);
	if (n > 0 && n < (int)sizeof(cfi_name)) {
		unsigned long jt = kallsyms_lookup_name(cfi_name);
		if (jt)
			return (void *)jt;
	}

	struct kp_variant_ctx ctx = { .name = name, .name_len = strlen(name) };

	ctx.exact = kallsyms_lookup_name(name);
	if (ctx.exact)
		return (void *)ctx.exact;
	if (kp_on_each_symbol) {
		kp_on_each_symbol(kp_variant_cb, &ctx);
		return (void *)ctx.variant;
	}
	return NULL;
}

void kp_symres_init(void)
{
	kp_on_each_symbol = (kp_kallsyms_on_each_symbol_t)kallsyms_lookup_name("kallsyms_on_each_symbol");
	logki("symbol resolver ready (on_each_symbol=%px)\n", kp_on_each_symbol);
}
