/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Runtime symbol resolver for the LKM. A loadable module can only link against
 * EXPORT_SYMBOL symbols, but KP needs non-exported ones (sys_call_table,
 * init_mm, hook targets ...). On GKI kernels kallsyms_lookup_name is exported
 * to modules, so it is the bootstrap; kallsyms_on_each_symbol is recovered by
 * name for CFI/llvm-mangled variant matching.
 */
#ifndef _KP_LKM_SYMBOL_RESOLVER_H_
#define _KP_LKM_SYMBOL_RESOLVER_H_
#include <linux/types.h>

/* Initialize the resolver (recover kallsyms_on_each_symbol). */
void kp_symres_init(void);

/* Exact-name kernel symbol lookup. Returns 0 if not found. */
unsigned long kp_resolve_symbol(const char *name);

/* Lookup that also accepts CFI/llvm-mangled variants of @name
 * ("name.cfi_jt" on < 6.1, "name.llvm.<hash>" on newer). Prefers an exact
 * match. Returns NULL if nothing matches. */
void *kp_resolve_symbol_variant(const char *name);

#endif /* _KP_LKM_SYMBOL_RESOLVER_H_ */
