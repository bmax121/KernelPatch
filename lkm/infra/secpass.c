// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Port of kernel/patch/common/secpass.c — CFI-bypass for the LKM.
 * Hooks report_cfi_failure / __cfi_slowpath_diag so that a CFI mismatch
 * on LKM text / hook trampoline / KPM memory degrades to a WARN instead
 * of panicking the kernel.
 */
#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/types.h>

#include "../include/kp_lkm.h"
#include "../kpm/module.h"
#include <hook.h>

struct pt_regs;

/* Is @target inside the LKM's own module image (text/data/rodata)? */
static bool kp_target_in_module(unsigned long target)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	/* 6.4+ replaced core_layout/init_layout with a per-type mem[] array. */
	enum mod_mem_type type;

	for (type = MOD_TEXT; type < MOD_MEM_NUM_TYPES; type++) {
		struct module_memory *m = &THIS_MODULE->mem[type];
		if (m->base &&
		    target >= (unsigned long)m->base &&
		    target < (unsigned long)m->base + m->size)
			return true;
	}
#else
	if (target >= (unsigned long)THIS_MODULE->core_layout.base &&
	    target < (unsigned long)THIS_MODULE->core_layout.base +
			      THIS_MODULE->core_layout.size)
		return true;

	/* Init section (freed after module init, but safe to check). */
	if (THIS_MODULE->init_layout.base &&
	    target >= (unsigned long)THIS_MODULE->init_layout.base &&
	    target < (unsigned long)THIS_MODULE->init_layout.base +
			      THIS_MODULE->init_layout.size)
		return true;
#endif
	return false;
}

/* Check if the CFI-mismatch target is in LKM-controlled memory. */
static bool kp_should_cfi_pass(unsigned long target)
{
	if (kp_target_in_module(target))
		return true;

	/* Loaded / loading KPM images and the callback-trampoline page. KPM code
	 * is no registered module, so Qualcomm's find_check_fn() and the KCFI
	 * slowpath would otherwise reject it. */
	if (kp_kpm_cfi_allowed_addr(target))
		return true;

	return false;
}

/* ---- find_check_fn (Qualcomm kallsyms/CFI hardening) ------------------ */

typedef void (*kp_cfi_check_fn)(uint64_t id, void *ptr);
typedef kp_cfi_check_fn (*kp_find_check_fn_t)(unsigned long addr);

static kp_find_check_fn_t __backup_find_check_fn;

__attribute__((no_sanitize("cfi")))
static void kp_noop_cfi_check(uint64_t id, void *ptr)
{
	(void)id;
	(void)ptr;
}

/* Qualcomm's kallsyms_on_each_symbol() validates the callback address through
 * find_check_fn() and panics ("CFI failure (target: %pS)") when it is neither
 * kernel text nor a registered module. For KP-managed addresses (the KPM image
 * and the kallsyms bti-trampoline page) return a no-op check function so the
 * iteration proceeds. */
__attribute__((no_sanitize("cfi")))
static kp_cfi_check_fn __replace_find_check_fn(unsigned long addr)
{
	if (kp_should_cfi_pass(addr))
		return kp_noop_cfi_check;
	if (__backup_find_check_fn)
		return __backup_find_check_fn(addr);
	return kp_noop_cfi_check;
}

/* ---- report_cfi_failure (6.1+) ---------------------------------------- */

static int (*__backup_report_cfi_failure)(struct pt_regs *, unsigned long,
					  unsigned long *, u32);

__attribute__((no_sanitize("cfi")))
static int __replace_report_cfi_failure(struct pt_regs *regs, unsigned long addr,
					unsigned long *target, u32 type)
{
	if (kp_should_cfi_pass(*target))
		return BUG_TRAP_TYPE_WARN;
	return __backup_report_cfi_failure(regs, addr, target, type);
}

/* ---- __cfi_slowpath_diag / __cfi_slowpath (5.10+) -------------------- */

static void (*__backup_cfi_slowpath)(uint64_t id, void *ptr, void *diag);

__attribute__((no_sanitize("cfi")))
static void __replace_cfi_slowpath(uint64_t id, void *ptr, void *diag)
{
	if (kp_should_cfi_pass((unsigned long)ptr))
		return;
	__backup_cfi_slowpath(id, ptr, diag);
}

/* ---- public ----------------------------------------------------------- */

static unsigned long kp_find_check_fn_addr;
static unsigned long kp_report_cfi_failure_addr;
static unsigned long kp_cfi_slowpath_addr;

int kp_bypass_kcfi(void)
{
	int rc = 0;

	unsigned long addr = kallsyms_lookup_name("find_check_fn");
	if (addr) {
		kp_find_check_fn_addr = addr;
		rc = hook((void *)addr, (void *)__replace_find_check_fn,
			  (void **)&__backup_find_check_fn);
		if (rc)
			logkw("hook find_check_fn error: %d\n", rc);
	} else {
		logkw("find_check_fn not found; KPM kallsyms CFI check unshielded\n");
	}

	addr = kallsyms_lookup_name("report_cfi_failure");
	if (addr) {
		kp_report_cfi_failure_addr = addr;
		rc = hook((void *)addr, (void *)__replace_report_cfi_failure,
			  (void **)&__backup_report_cfi_failure);
		if (rc)
			logkw("hook report_cfi_failure error: %d\n", rc);
	}

	addr = kallsyms_lookup_name("__cfi_slowpath_diag");
	if (!addr)
		addr = kallsyms_lookup_name("__cfi_slowpath");
	if (addr) {
		kp_cfi_slowpath_addr = addr;
		rc = hook((void *)addr, (void *)__replace_cfi_slowpath,
			  (void **)&__backup_cfi_slowpath);
		if (rc)
			logkw("hook __cfi_slowpath_diag error: %d\n", rc);
	}

	logki("CFI bypass ready\n");
	return rc;
}

/* Remove the CFI bypass hooks so the module can be unloaded without leaving
 * branches into freed module memory (IABT). Call last on exit. */
void kp_bypass_kcfi_exit(void)
{
	if (kp_find_check_fn_addr) {
		unhook((void *)kp_find_check_fn_addr);
		kp_find_check_fn_addr = 0;
		__backup_find_check_fn = NULL;
	}
	if (kp_report_cfi_failure_addr) {
		unhook((void *)kp_report_cfi_failure_addr);
		kp_report_cfi_failure_addr = 0;
		__backup_report_cfi_failure = NULL;
	}
	if (kp_cfi_slowpath_addr) {
		unhook((void *)kp_cfi_slowpath_addr);
		kp_cfi_slowpath_addr = 0;
		__backup_cfi_slowpath = NULL;
	}
	logki("CFI bypass unhooked\n");
}
