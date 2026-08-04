// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */
#include "syscall_table.h"
#include "patch_memory.h"
#include "symbol_resolver.h"

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/string.h>

#include "../include/kp_lkm.h"

kp_syscall_fn_t *kp_sys_call_table;

int kp_syscall_table_init(void)
{
	/* sys_call_table is not exported; find it by name. On arm64 the symbol
	 * exists in kallsyms when CONFIG_KALLSYMS_ALL=y (GKI default). */
	kp_sys_call_table = (kp_syscall_fn_t *)kp_resolve_symbol("sys_call_table");
	if (!kp_sys_call_table) {
		logke("failed to resolve sys_call_table\n");
		return -ENOENT;
	}
	logki("sys_call_table at %px\n", kp_sys_call_table);
	return 0;
}

int kp_syscall_hook(int nr, kp_syscall_fn_t fn, kp_syscall_fn_t *orig)
{
	if (!kp_sys_call_table || nr < 0)
		return -EINVAL;

	kp_syscall_fn_t old = READ_ONCE(kp_sys_call_table[nr]);
	if (orig)
		*orig = old;

	/* sys_call_table lives in rodata; kp_patch_text walks init_mm and pokes
	 * through a fixmap under stop_machine. */
	int ret = kp_patch_text(&kp_sys_call_table[nr], &fn, sizeof(fn),
				KP_PATCH_TEXT_FLUSH_DCACHE);
	if (ret) {
		logke("patch sys_call_table[%d] failed: %d\n", nr, ret);
		return ret;
	}
	logki("hooked syscall %d: %px -> %px\n", nr, old, fn);
	return 0;
}

void kp_syscall_unhook(int nr, kp_syscall_fn_t orig)
{
	if (!kp_sys_call_table || nr < 0 || !orig)
		return;
	kp_patch_text(&kp_sys_call_table[nr], &orig, sizeof(orig), KP_PATCH_TEXT_FLUSH_DCACHE);
	logki("restored syscall %d\n", nr);
}
