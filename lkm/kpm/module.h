/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KernelPatch Module (KPM) loader for the LKM framework. The KPM ABI matches
 * KP's kernel/patch/module/module.c: a KPM is a relocatable ELF (ET_REL) with
 * .kpm.info/.kpm.init/.kpm.exit (and optional .kpm.ctl0/.kpm.ctl1/.kpm.event)
 * sections; undefined symbols are resolved from the running kernel.
 */
#ifndef _KP_LKM_KPM_MODULE_H_
#define _KP_LKM_KPM_MODULE_H_

#include <asm-generic/module.h>
#include <linux/elf.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/version.h>
#include <scdefs.h>

#include <kpmodule.h>

/* KPM ABI function types (from kpmodule.h): mod_initcall_t, mod_ctl0call_t,
 * mod_ctl1call_t, mod_exitcall_t, mod_eventcall_t. */

struct kp_load_info {
	struct {
		const char *base;
		unsigned long size;
		const char *name, *version, *license, *author, *description;
		char error_msg[KPM_LOAD_ERROR_MESSAGE_LEN];
	} info;
	const Elf_Ehdr *hdr;
	unsigned long len;
	Elf_Shdr *sechdrs;
	char *secstrings, *strtab;
	unsigned long symoffs, stroffs;
	struct {
		unsigned int sym, str, mod, info;
	} index;
};

struct kp_module {
	struct {
		const char *base, *name, *version, *license, *author, *description;
	} info;

	char *args, *ctl_args;

	mod_initcall_t *init;
	mod_ctl0call_t *ctl0;
	mod_ctl1call_t *ctl1;
	mod_exitcall_t *exit;
	mod_eventcall_t *event;

	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;

	void *start;

	struct list_head list;
};

/* Load a module from a kernel buffer, then call its init. @event is passed to
 * init as the event name (KP passes "load-file"). @reserved is the user KPM
 * load-result buffer (struct kpm_load_result), may be NULL. */
long kp_load_module(const void *data, int len, const char *args, const char *event,
		    void __user *reserved);

/* Load a module from a path (user file). */
long kp_load_module_path(const char *path, const char *args, void __user *reserved);

long kp_module_control0(const char *name, const char *ctl_args, char __user *out_msg, int outlen);
long kp_module_control1(const char *name, void *a1, void *a2, void *a3);
long kp_unload_module(const char *name, void __user *reserved);
long kp_notify_modules_event(const char *event, const char *args, void __user *reserved);

int kp_get_module_nums(void);
int kp_list_modules(char *out_names, int size);
int kp_get_module_info(const char *name, char *out_info, int size);

/* Init the module registry list. */
int kp_kpm_init(void);

/*
 * CFI / BTI shielding for KPM kallsyms iteration. On Qualcomm-hardened kernels
 * (cf. find_check_fn in the vendor kallsyms/CFI code) a callback address that
 * is neither kernel text nor inside a registered module makes the kernel panic
 * with "CFI failure (target: %pS)". KPM code lives in module_alloc'd memory
 * that is no registered module, so any kallsyms_on_each_symbol() iteration from
 * a KPM trips that check; a plain BLR into the bare-metal (non-BTI) callback
 * would additionally fault under BTI.
 *
 * kp_kpm_cfi_allowed_addr() reports whether an address falls inside a loaded /
 * currently-loading KPM image or the LKM's callback-trampoline page. The safe
 * kallsyms_on_each_symbol() stand-in (installed into the KPM symbol table) uses
 * that range check plus a bti-c trampoline to make the kernel call the KPM
 * callback without tripping either mitigation.
 */
struct module;
/* kallsyms_on_each_symbol() dropped the struct module * parameter from its
 * callback in 6.4 (3-arg since). Match the running kernel so the resolved
 * function pointer passes the kCFI type-hash check. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
typedef int (*kp_kallsyms_cb_t)(void *, const char *, unsigned long);
#else
typedef int (*kp_kallsyms_cb_t)(void *, const char *, struct module *, unsigned long);
#endif
bool kp_kpm_cfi_allowed_addr(unsigned long addr);
int kp_kpm_safe_kallsyms_on_each_symbol(kp_kallsyms_cb_t fn, void *data);

#endif /* _KP_LKM_KPM_MODULE_H_ */
