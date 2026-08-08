// SPDX-License-Identifier: GPL-2.0-or-later
/* Compatibility symbols exported by the in-kernel KP runtime to KPMs. */
#include "symbols.h"

#include <linux/cred.h>
#include <linux/gfp.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
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
#include "../infra/syscall_table.h"
#include "../supercall/sucompat.h"
#include "../supercall/kstorage.h"
#include "module.h"

#include <asm/thread_info.h>
#include <hook.h>

static u32 kp_kpm_kver = LINUX_VERSION_CODE;
static u32 kp_kpm_kpver = KP_LKM_VERSION_CODE;
static int kp_kpm_thread_size = THREAD_SIZE;
static int kp_kpm_thread_info_in_task = 1;
static int kp_kpm_sp_el0_is_current = 1;
static int kp_kpm_sp_el0_is_thread_info;
static int kp_kpm_task_in_thread_info_offset = -1;
/* KP ABI stack-layout facts (arm64 GKI: task->stack + THREAD_SIZE is the end
 * of stack, pt_regs sits just below it). */
static int kp_kpm_stack_in_task_offset = offsetof(struct task_struct, stack);
static int kp_kpm_stack_end_offset = THREAD_SIZE;
static int kp_kpm_has_syscall_wrapper;

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

/* KPM headers declare printk/kallsyms_lookup_name/kallsyms_on_each_symbol as
 * function-pointer *variables* (extern void (*printk)(...)), so KPMs load the
 * pointer *stored at* the symbol address (adrp + ldr [x,#lo12] + blr).  The
 * symbols must therefore resolve to the address of a writable slot holding the
 * function pointer, not to the function's own code address (which would make
 * the ldr read the function prologue bytes as a pointer). */
static int (*kp_kpm_printk_fn)(const char *fmt, ...);
static unsigned long (*kp_kpm_kallsyms_lookup_name_fn)(const char *name);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
/* 6.4+ dropped the struct module * param from kallsyms_on_each_symbol's
 * callback; match the running kernel so the resolved pointer's kCFI type
 * hash lines up with kp_kpm_safe_kallsyms_on_each_symbol(). */
static int (*kp_kpm_kallsyms_on_each_symbol_fn)(
	int (*fn)(void *, const char *, unsigned long), void *data);
#else
static int (*kp_kpm_kallsyms_on_each_symbol_fn)(
	int (*fn)(void *, const char *, struct module *, unsigned long), void *data);
#endif

/* Same for the kf_* kfuncs (lib/string.c etc.): kfunc_def(name) is
 * (*kf_name), so a KPM referencing e.g. strncat accesses the pointer-variable
 * symbol kf_strncat and needs a slot, populated from the running kernel. */
#define KP_KPM_KFUNC_INIT(name) \
	kf_##name = (typeof(kf_##name))kallsyms_lookup_name(#name)
#define KP_KPM_KFUNC_ENTRY(name) \
	{ "kf_" #name, (unsigned long)&kf_##name }

static int (*kf_sprintf)(char *buf, const char *fmt, ...);
static int (*kf_snprintf)(char *buf, size_t size, const char *fmt, ...);
static int (*kf_vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);
static char *(*kf_strcpy)(char *dest, const char *src);
static char *(*kf_strncpy)(char *dest, const char *src, size_t count);
static char *(*kf_strncat)(char *dest, const char *src, size_t count);
static int (*kf_strcmp)(const char *cs, const char *ct);
static int (*kf_strncmp)(const char *cs, const char *ct, size_t count);
static size_t (*kf_strlen)(const char *s);
static size_t (*kf_strnlen)(const char *s, size_t count);
static char *(*kf_strchr)(const char *s, int c);
static char *(*kf_strrchr)(const char *s, int c);
static char *(*kf_strstr)(const char *s1, const char *s2);
static void *(*kf_memset)(void *s, int c, size_t count);
static void *(*kf_memcpy)(void *dest, const void *src, size_t count);
static void *(*kf_memmove)(void *dest, const void *src, size_t count);
static int (*kf_memcmp)(const void *cs, const void *ct, size_t count);
static char *(*kf_kstrdup)(const char *s, gfp_t gfp);
static void *(*kf_kmemdup)(const void *src, size_t len, gfp_t gfp);
static char *(*kf_kasprintf)(gfp_t gfp, const char *fmt, ...);
static void *(*kf_memchr)(const void *s, int c, size_t n);
static char *(*kf_strcat)(char *dest, const char *src);

/* mm_struct offsets (mirrors kpimg's linux/mm_types.h) */
struct kp_kpm_mm_struct_offset {
	s16 mmap_base_offset;
	s16 task_size_offset;
	s16 pgd_offset;
	s16 map_count_offset;
	s16 total_vm_offset;
	s16 locked_vm_offset;
	s16 pinned_vm_offset;
	s16 data_vm_offset;
	s16 exec_vm_offset;
	s16 stack_vm_offset;
	s16 start_code_offset, end_code_offset, start_data_offset, end_data_offset;
	s16 start_brk_offset, brk_offset, start_stack_offset;
	s16 arg_start_offset, arg_end_offset, env_start_offset, env_end_offset;
};
static struct kp_kpm_mm_struct_offset kp_kpm_mm_struct_offset;

/* Syscall hooks: the LKM patches sys_call_table entries (fp path). */
static int kp_kpm_has_config_compat;

static uintptr_t kp_kpm_syscalln_name_addr(int nr, int is_compat)
{
	if (!is_compat && kp_sys_call_table)
		return kp_sys_call_table[nr];
	return 0;
}

static uintptr_t kp_kpm_syscalln_addr(int nr, int is_compat)
{
	if (!is_compat && kp_sys_call_table)
		return kp_sys_call_table[nr];
	return kp_kpm_syscalln_name_addr(nr, is_compat);
}

static int kp_kpm_hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
	/* Inline-hook the syscall function itself (kpimg's inline_wrap_syscalln).
	 * fp_hook_wrap lives in fphook.c which the LKM does not compile. */
	uintptr_t addr = kp_kpm_syscalln_addr(nr, 0);
	if (!addr)
		return -ENOENT;
	return hook_wrap((void *)addr, narg, before, after, udata);
}

static void kp_kpm_unhook_syscalln(int nr, void *before, void *after)
{
	uintptr_t addr = kp_kpm_syscalln_addr(nr, 0);
	if (addr)
		hook_unwrap((void *)addr, before, after);
}

static int kp_kpm_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
	(void)nr; (void)narg; (void)before; (void)after; (void)udata;
	return -ENOSYS; /* no compat table on arm64 GKI */
}

static void kp_kpm_unhook_compat_syscalln(int nr, void *before, void *after)
{
	(void)nr; (void)before; (void)after;
}

/* task_pt_regs */
static struct pt_regs *kp_kpm_task_pt_reg(struct task_struct *task)
{
	unsigned long stack = (unsigned long)task_stack_page(task);
	return (struct pt_regs *)(THREAD_SIZE + stack - sizeof(struct pt_regs));
}

/* SU allowlist / exclude (mirrors kpimg sucompat.c) */
static int kp_kpm_is_su_allow_uid(uid_t uid)
{
	return kp_is_su_allow_uid(uid) ? 1 : 0;
}

/* Exclude list lives in the sucompat layer (group KSTORAGE_EXCLUDE_LIST_GROUP);
 * these thin wrappers are what KPMs see through the compatibility symbol
 * table, so the auto-loaded package_config excludes are visible to them. */
static int kp_kpm_get_ap_mod_exclude(uid_t uid)
{
	return kp_su_get_ap_mod_exclude(uid);
}

static int kp_kpm_set_ap_mod_exclude(uid_t uid, int exclude)
{
	return kp_su_set_ap_mod_exclude(uid, exclude);
}

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
	{ "printk", (unsigned long)&kp_kpm_printk_fn },
	{ "kallsyms_lookup_name", (unsigned long)&kp_kpm_kallsyms_lookup_name_fn },
	{ "kallsyms_on_each_symbol", (unsigned long)&kp_kpm_kallsyms_on_each_symbol_fn },
	KP_KPM_KFUNC_ENTRY(sprintf),
	KP_KPM_KFUNC_ENTRY(snprintf),
	KP_KPM_KFUNC_ENTRY(vsnprintf),
	KP_KPM_KFUNC_ENTRY(strcpy),
	KP_KPM_KFUNC_ENTRY(strncpy),
	KP_KPM_KFUNC_ENTRY(strncat),
	KP_KPM_KFUNC_ENTRY(strcmp),
	KP_KPM_KFUNC_ENTRY(strncmp),
	KP_KPM_KFUNC_ENTRY(strlen),
	KP_KPM_KFUNC_ENTRY(strnlen),
	KP_KPM_KFUNC_ENTRY(strchr),
	KP_KPM_KFUNC_ENTRY(strrchr),
	KP_KPM_KFUNC_ENTRY(strstr),
	KP_KPM_KFUNC_ENTRY(memset),
	KP_KPM_KFUNC_ENTRY(memcpy),
	KP_KPM_KFUNC_ENTRY(memmove),
	KP_KPM_KFUNC_ENTRY(memcmp),
	KP_KPM_KFUNC_ENTRY(kstrdup),
	KP_KPM_KFUNC_ENTRY(kmemdup),
	KP_KPM_KFUNC_ENTRY(kasprintf),
	KP_KPM_KFUNC_ENTRY(memchr),
	KP_KPM_KFUNC_ENTRY(strcat),
	{ "mm_struct_offset", (unsigned long)&kp_kpm_mm_struct_offset },
	{ "has_config_compat", (unsigned long)&kp_kpm_has_config_compat },
	{ "has_syscall_wrapper", (unsigned long)&kp_kpm_has_syscall_wrapper },
	{ "stack_in_task_offset", (unsigned long)&kp_kpm_stack_in_task_offset },
	{ "stack_end_offset", (unsigned long)&kp_kpm_stack_end_offset },
	{ "hook_syscalln", (unsigned long)kp_kpm_hook_syscalln },
	{ "unhook_syscalln", (unsigned long)kp_kpm_unhook_syscalln },
	{ "hook_compat_syscalln", (unsigned long)kp_kpm_hook_compat_syscalln },
	{ "unhook_compat_syscalln", (unsigned long)kp_kpm_unhook_compat_syscalln },
	{ "syscalln_addr", (unsigned long)kp_kpm_syscalln_addr },
	{ "syscalln_name_addr", (unsigned long)kp_kpm_syscalln_name_addr },
	{ "_task_pt_reg", (unsigned long)kp_kpm_task_pt_reg },
	{ "is_su_allow_uid", (unsigned long)kp_kpm_is_su_allow_uid },
	{ "get_ap_mod_exclude", (unsigned long)kp_kpm_get_ap_mod_exclude },
	{ "set_ap_mod_exclude", (unsigned long)kp_kpm_set_ap_mod_exclude },
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
	kp_kpm_printk_fn = kp_kpm_printk;
	kp_kpm_kallsyms_lookup_name_fn = kallsyms_lookup_name;
	/* Route KPM kallsyms iteration through the bti-c trampoline + CFI shield
	 * so Qualcomm's find_check_fn() panic and the BTI fault on bare-metal
	 * callbacks are avoided. */
	kp_kpm_kallsyms_on_each_symbol_fn = kp_kpm_safe_kallsyms_on_each_symbol;

	KP_KPM_KFUNC_INIT(sprintf);
	KP_KPM_KFUNC_INIT(snprintf);
	KP_KPM_KFUNC_INIT(vsnprintf);
	KP_KPM_KFUNC_INIT(strcpy);
	KP_KPM_KFUNC_INIT(strncpy);
	KP_KPM_KFUNC_INIT(strncat);
	KP_KPM_KFUNC_INIT(strcmp);
	KP_KPM_KFUNC_INIT(strncmp);
	KP_KPM_KFUNC_INIT(strlen);
	KP_KPM_KFUNC_INIT(strnlen);
	KP_KPM_KFUNC_INIT(strchr);
	KP_KPM_KFUNC_INIT(strrchr);
	KP_KPM_KFUNC_INIT(strstr);
	KP_KPM_KFUNC_INIT(memset);
	KP_KPM_KFUNC_INIT(memcpy);
	KP_KPM_KFUNC_INIT(memmove);
	KP_KPM_KFUNC_INIT(memcmp);
	KP_KPM_KFUNC_INIT(kstrdup);
	KP_KPM_KFUNC_INIT(kmemdup);
	KP_KPM_KFUNC_INIT(kasprintf);
	KP_KPM_KFUNC_INIT(memchr);
	KP_KPM_KFUNC_INIT(strcat);

	/* mm_struct offsets (5.15 arm64) */
	kp_kpm_mm_struct_offset.mmap_base_offset = offsetof(struct mm_struct, mmap_base);
	kp_kpm_mm_struct_offset.task_size_offset = offsetof(struct mm_struct, task_size);
	kp_kpm_mm_struct_offset.pgd_offset = offsetof(struct mm_struct, pgd);
	kp_kpm_mm_struct_offset.map_count_offset = offsetof(struct mm_struct, map_count);
	kp_kpm_mm_struct_offset.total_vm_offset = offsetof(struct mm_struct, total_vm);
	kp_kpm_mm_struct_offset.locked_vm_offset = offsetof(struct mm_struct, locked_vm);
	kp_kpm_mm_struct_offset.pinned_vm_offset = offsetof(struct mm_struct, pinned_vm);
	kp_kpm_mm_struct_offset.data_vm_offset = offsetof(struct mm_struct, data_vm);
	kp_kpm_mm_struct_offset.exec_vm_offset = offsetof(struct mm_struct, exec_vm);
	kp_kpm_mm_struct_offset.stack_vm_offset = offsetof(struct mm_struct, stack_vm);
	kp_kpm_mm_struct_offset.start_code_offset = offsetof(struct mm_struct, start_code);
	kp_kpm_mm_struct_offset.end_code_offset = offsetof(struct mm_struct, end_code);
	kp_kpm_mm_struct_offset.start_data_offset = offsetof(struct mm_struct, start_data);
	kp_kpm_mm_struct_offset.end_data_offset = offsetof(struct mm_struct, end_data);
	kp_kpm_mm_struct_offset.start_brk_offset = offsetof(struct mm_struct, start_brk);
	kp_kpm_mm_struct_offset.brk_offset = offsetof(struct mm_struct, brk);
	kp_kpm_mm_struct_offset.start_stack_offset = offsetof(struct mm_struct, start_stack);
	kp_kpm_mm_struct_offset.arg_start_offset = offsetof(struct mm_struct, arg_start);
	kp_kpm_mm_struct_offset.arg_end_offset = offsetof(struct mm_struct, arg_end);
	kp_kpm_mm_struct_offset.env_start_offset = offsetof(struct mm_struct, env_start);
	kp_kpm_mm_struct_offset.env_end_offset = offsetof(struct mm_struct, env_end);

	kp_kpm_has_config_compat = 0;

	/* arm64 GKI: syscalls go through __arm64_sys_* wrappers, so the KPM must
	 * parse syscall args with the wrapper ABI (narg + 1). */
	kp_kpm_has_syscall_wrapper = 0;
	if (kallsyms_lookup_name("__arm64_sys_openat"))
		kp_kpm_has_syscall_wrapper = 1;

	logki("kpm stack facts: stack_in_task=%d stack_end=%d has_syscall_wrapper=%d\n",
	      kp_kpm_stack_in_task_offset, kp_kpm_stack_end_offset,
	      kp_kpm_has_syscall_wrapper);

	logki("kpm compatibility symbol table ready (%zu symbols) printk=%px "
	      "kallsyms_lookup_name=%px kf_strncat=%px kf_strcmp=%px\n",
	      ARRAY_SIZE(kp_kpm_symbols), kp_kpm_printk_fn, kp_kpm_kallsyms_lookup_name_fn,
	      kf_strncat, kf_strcmp);
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
