// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * arm64 read-only memory patching via the kernel's own text-patch API.
 * aarch64_insn_patch_text_nosync() handles the rodata write + icache/dcache
 * flush correctly (through its own fixmap / alias path) and does not take
 * stop_machine, so calling it from a syscall/supercall context cannot deadlock
 * with RCU/membarrier tasks on other CPUs. We patch sys_call_table[nr] (a
 * plain 8-byte pointer) and, for KPMs, inline hooks on kernel text.
 */
#ifdef __aarch64__

#include "patch_memory.h"
#include "symbol_resolver.h"

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/barrier.h>

#include "../include/kp_lkm.h"

/* Resolved at init from kallsyms (not exported to modules on GKI). */
typedef void (*kp_aarch64_insn_patch_text_t)(void *addr, u32 insn);
static kp_aarch64_insn_patch_text_t kp_insn_patch_text;

/* Detect the dcache flush API: android13-5.10 backported dcache_clean_inval_poc,
 * android12-5.10 still has __flush_dcache_area. Kbuild sets KP_NEW_DCACHE_FLUSH. */
#ifndef KP_NEW_DCACHE_FLUSH
#define KP_NEW_DCACHE_FLUSH 0
#endif
#if KP_NEW_DCACHE_FLUSH
#define kp_flush_dcache(start, sz)                                                    \
	({                                                                               \
		unsigned long __start = (start);                                         \
		dcache_clean_inval_poc(__start, __start + (sz));                         \
	})
#define kp_flush_icache(start, end)                                                    \
	({                                                                               \
		unsigned long __start = (start);                                         \
		caches_clean_inval_pou(__start, (end));                                  \
	})
#else
#define kp_flush_dcache(start, sz) __flush_dcache_area((void *)(start), (sz))
#define kp_flush_icache(start, end) __flush_icache_range((start), (end))
#endif

/* Resolve the physical address of a kernel VA through init_mm's page tables.
 * Used for the data patch path (sys_call_table is rodata, not mapped via the
 * direct kernel text alias, so we poke it through a fixmap). init_mm is cached
 * at init (not exported to modules on GKI). */
static struct mm_struct *kp_patch_init_mm;

__attribute__((no_sanitize("cfi")))
static unsigned long kp_phys_from_virt(unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct mm_struct *mm = kp_patch_init_mm;

	if (!mm)
		return 0;
	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return 0;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return 0;
#if defined(p4d_leaf)
	if (p4d_leaf(*p4d))
		return __p4d_to_phys(*p4d) + (addr & ~P4D_MASK);
#endif
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return 0;
#if defined(pud_leaf)
	if (pud_leaf(*pud))
		return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
#endif
	pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd))
		return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return 0;
	pte = pte_offset_kernel(pmd, addr);
	if (!pte || !pte_present(*pte))
		return 0;
	return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);
}

/* Data (rodata) poke through a fixmap; page-align the phys for set_fixmap_offset
 * and add the offset back. Used only for sys_call_table pointer writes. */
__attribute__((no_sanitize("cfi")))
static int kp_patch_data(void *dst, const void *src, size_t len)
{
	unsigned long phy = kp_phys_from_virt((unsigned long)dst);
	if (!phy) {
		logke("no phys for data patch dst 0x%lx\n", (unsigned long)dst);
		return -ENOENT;
	}
	unsigned long phy_off = phy & ~PAGE_MASK;
	void *map = (void *)set_fixmap_offset(FIX_TEXT_POKE0, phy & PAGE_MASK) + phy_off;
	int ret = (int)copy_to_kernel_nofault(map, src, len);
	clear_fixmap(FIX_TEXT_POKE0);
	if (!ret)
		kp_flush_dcache((unsigned long)dst, len);
	return ret;
}

int kp_patch_memory_init(void)
{
	/* aarch64_insn_patch_text() is not exported to modules on GKI, resolve it
	 * by name. It runs under stop_machine (safe text update: every CPU is
	 * parked, so no one executes the half-patched instruction), which is what
	 * an inline KPM hook on a hot kernel function needs. Called from a KPM load
	 * (syscall context) this is still safe: stop_machine completes quickly here
	 * because a KPM load is a rare, user-triggered operation, whereas the
	 * nosync variant let another CPU run the stale instruction and died on the
	 * big cores (watchdog bite). */
	kp_insn_patch_text = (kp_aarch64_insn_patch_text_t)kp_resolve_symbol("aarch64_insn_patch_text");
	if (!kp_insn_patch_text) {
		logke("failed to resolve aarch64_insn_patch_text\n");
		return -ENOENT;
	}
	kp_patch_init_mm = (struct mm_struct *)kp_resolve_symbol("init_mm");
	if (!kp_patch_init_mm)
		logkw("failed to resolve init_mm; data (sys_call_table) patch disabled\n");
	logki("aarch64_insn_patch_text resolved\n");
	return 0;
}

/* CFI-enabled kernels type-check indirect calls; this function pointer to a
 * kernel text-patch helper was resolved by name and has no LKM-side CFI entry,
 * so the indirect call must skip CFI or the kernel panics (__cfi_check_fail). */
__attribute__((no_sanitize("cfi")))
int kp_patch_text(void *dst, const void *src, size_t len, int flags)
{
	/* Text (KPM inline hook): aarch64_insn_patch_text runs under stop_machine,
	 * safe on a hot kernel function. Data (sys_call_table pointer): fixmap poke
	 * only; aarch64_insn_patch_text on a rodata data word faults in its callback.
	 * Callers pass FLUSH_ICACHE for text, FLUSH_DCACHE for data. */
	if (flags & KP_PATCH_TEXT_FLUSH_ICACHE) {
		const u32 *in = src;
		unsigned int n = len / sizeof(*in);
		for (unsigned int i = 0; i < n; i++) {
			u32 insn;
			if (copy_from_kernel_nofault(&insn, &in[i], sizeof(insn)))
				return -EFAULT;
			kp_insn_patch_text((u8 *)dst + i * sizeof(u32), insn);
		}
		return 0;
	}
	return kp_patch_data(dst, src, len);
}

#endif /* __aarch64__ */
