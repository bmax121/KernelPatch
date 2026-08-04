// SPDX-License-Identifier: GPL-2.0-or-later
/* Compatibility symbols exported by the in-kernel KP runtime to KPMs. */
#include "symbols.h"

#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#include <linux/stdarg.h>
#else
/* linux/stdarg.h is absent before 5.14; the repo's kernel/include/stdarg.h
 * (found via -I) provides the same __builtin_va_* wrappers. */
#include <stdarg.h>
#endif
#include "../include/kp_lkm.h"
#include "../infra/symbol_resolver.h"
#include "../infra/patch_memory.h"

#include <asm/thread_info.h>
#include <hook.h>

static u32 kp_kpm_kver = LINUX_VERSION_CODE;
static u32 kp_kpm_kpver = KP_LKM_VERSION_CODE;
static int kp_kpm_thread_size = THREAD_SIZE;
static int kp_kpm_thread_info_in_task = 1;
static int kp_kpm_sp_el0_is_current = 1;
static int kp_kpm_sp_el0_is_thread_info;
static int kp_kpm_task_in_thread_info_offset = -1;

struct kp_kpm_task_struct_offset {
	s16 pid_offset, tgid_offset, thread_pid_offset, ptracer_cred_offset;
	s16 real_cred_offset, cred_offset, comm_offset, fs_offset, files_offset;
	s16 loginuid_offset, sessionid_offset, seccomp_offset, security_offset;
	s16 stack_offset, tasks_offset, mm_offset, active_mm_offset;
};

static struct kp_kpm_task_struct_offset kp_kpm_task_struct_offset = {
	.pid_offset = offsetof(struct task_struct, pid),
	.tgid_offset = offsetof(struct task_struct, tgid),
	.thread_pid_offset = offsetof(struct task_struct, thread_pid),
	.ptracer_cred_offset = offsetof(struct task_struct, ptracer_cred),
	.real_cred_offset = offsetof(struct task_struct, real_cred),
	.cred_offset = offsetof(struct task_struct, cred),
	.comm_offset = offsetof(struct task_struct, comm),
	.fs_offset = offsetof(struct task_struct, fs),
	.files_offset = offsetof(struct task_struct, files),
	.loginuid_offset = -1,
	.sessionid_offset = -1,
	.seccomp_offset = offsetof(struct task_struct, seccomp),
	.security_offset = -1,
	.stack_offset = offsetof(struct task_struct, stack),
	.tasks_offset = offsetof(struct task_struct, tasks),
	.mm_offset = offsetof(struct task_struct, mm),
	.active_mm_offset = offsetof(struct task_struct, active_mm),
};

static u64 *kp_kpm_pgtable_entry(u64 pgd_addr, u64 va)
{
	pgd_t *pgd = (pgd_t *)pgd_addr + pgd_index(va);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
	if (pud_sect(*pud))
		return (u64 *)pud;
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
	if (pmd_sect(*pmd))
		return (u64 *)pmd;
	pte = pte_offset_kernel(pmd, va);
	return pte ? (u64 *)pte : NULL;
}

__attribute__((no_sanitize("cfi")))
static int kp_kpm_printk(const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	int rc;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	rc = printk("%pV", &vaf);
	va_end(args);
	return rc;
}

static int kp_kpm_sprintf(char *buf, const char *fmt, ...)
{
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = vsprintf(buf, fmt, args);
	va_end(args);
	return rc;
}

static int kp_kpm_copy_to_user(void __user *to, const void *from, int len)
{
	return copy_to_user(to, from, len) ? 0 : len;
}

static long kp_kpm_strncpy_from_user(char *dst, const char __user *src, long count)
{
	long rc = strncpy_from_user(dst, src, count);

	if (rc >= count) {
		dst[count - 1] = '\0';
		return count;
	}
	return rc > 0 ? rc + 1 : rc;
}

static uid_t kp_kpm_current_uid(void)
{
	return from_kuid(current_user_ns(), current_uid());
}

/* KP kfuncs that KPMs may import (kpimg exports these via baselib / hotpatch).
 * kf_strncat mirrors lib_strncat; hotpatch_nosync patches one instruction. */
static char *kp_kpm_strncat(char *dst, const char *src, size_t n)
{
	return strncat(dst, src, n);
}

static long kp_kpm_hotpatch_nosync(void *addr, uint32_t value)
{
	uint32_t insn = value;
	return kp_patch_text(addr, &insn, sizeof(insn),
			     KP_PATCH_TEXT_FLUSH_DCACHE | KP_PATCH_TEXT_FLUSH_ICACHE);
}

struct kp_kpm_symbol {
	const char *name;
	unsigned long addr;
};

static struct kp_kpm_symbol kp_kpm_symbols[] = {
	{ "compat_copy_to_user", (unsigned long)kp_kpm_copy_to_user },
	{ "compat_strncpy_from_user", (unsigned long)kp_kpm_strncpy_from_user },
	{ "current_uid", (unsigned long)kp_kpm_current_uid },
	{ "kver", (unsigned long)&kp_kpm_kver },
	{ "kpver", (unsigned long)&kp_kpm_kpver },
	{ "thread_size", (unsigned long)&kp_kpm_thread_size },
	{ "thread_info_in_task", (unsigned long)&kp_kpm_thread_info_in_task },
	{ "sp_el0_is_current", (unsigned long)&kp_kpm_sp_el0_is_current },
	{ "sp_el0_is_thread_info", (unsigned long)&kp_kpm_sp_el0_is_thread_info },
	{ "task_in_thread_info_offset", (unsigned long)&kp_kpm_task_in_thread_info_offset },
	{ "task_struct_offset", (unsigned long)&kp_kpm_task_struct_offset },
	{ "pgtable_entry", (unsigned long)kp_kpm_pgtable_entry },
	{ "printk", (unsigned long)kp_kpm_printk },
	{ "kf_sprintf", (unsigned long)kp_kpm_sprintf },
	{ "kf_strncat", (unsigned long)kp_kpm_strncat },
	{ "hotpatch_nosync", (unsigned long)kp_kpm_hotpatch_nosync },
	{ "hook_wrap", (unsigned long)hook_wrap },
	{ "hook_unwrap_remove", (unsigned long)hook_unwrap_remove },
	{ "hook_chain_add", (unsigned long)hook_chain_add },
	{ "hook_chain_remove", (unsigned long)hook_chain_remove },
	{ "hook_prepare", (unsigned long)hook_prepare },
	{ "hook_install", (unsigned long)hook_install },
	{ "hook_uninstall", (unsigned long)hook_uninstall },
	{ "hook", (unsigned long)hook },
	{ "unhook", (unsigned long)unhook },
};

int kp_kpm_symbols_init(void)
{
	logki("kpm compatibility symbol table ready (%zu symbols)\n",
	      ARRAY_SIZE(kp_kpm_symbols));
	return 0;
}

unsigned long kp_kpm_symbol_lookup(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(kp_kpm_symbols); i++) {
		if (!strcmp(name, kp_kpm_symbols[i].name))
			return kp_kpm_symbols[i].addr;
	}
	return 0;
}
