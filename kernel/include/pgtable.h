/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_PGTABLE_H_
#define _KP_PGTABLE_H_

#include <ktypes.h>

#ifdef CONFIG_X86_64

/* x86_64 PTE bits (4-level paging, 4K pages).
 *
 * Several arm64 PTE names have no x86 equivalent with the same polarity, so they
 * are deliberately not defined here rather than aliased to a bit that means the
 * opposite:
 *   PTE_RDONLY  arm64 sets it to deny writes, x86 bit 1 grants them.  Use
 *               PTE_WRITE and clear it instead.
 *   PTE_NG      arm64 sets it to make an entry non-global, x86 bit 8 (PTE_GLOBAL)
 *               sets it to make one global.  Opposite sense.
 *   PTE_TYPE_*  x86 has no page/table type field in a leaf entry.
 */
#define PTE_VALID    (1ul << 0)   /* Present */
#define PTE_WRITE    (1ul << 1)   /* R/W: set means writable */
#define PTE_USER     (1ul << 2)   /* U/S */
#define PTE_AF       (1ul << 5)   /* Accessed */
#define PTE_DIRTY    (1ul << 6)   /* Dirty */
#define PTE_GLOBAL   (1ul << 8)   /* Global: not flushed by a CR3 reload */
#define PTE_PXN      (1ul << 63)  /* NX (No-Execute) */
#define PTE_SHARED   (0)
#define PTE_GP       (0)
#define PTE_TABLE_BIT (1ul << 0)
#define PTE_CONT     (0)

#define pte_valid_cont(pte) 0

#define CONT_PTES      1
#define CONT_PTE_MASK  (~0ul)

#define sev() asm volatile("" ::: "memory")
#define wfe() asm volatile("pause" ::: "memory")
#define wfi() asm volatile("hlt" ::: "memory")

#define isb()  asm volatile("" ::: "memory")
#define dmb(opt) asm volatile("mfence" ::: "memory")
#define dsb(opt) asm volatile("mfence" ::: "memory")

/* A CR3 reload does not invalidate global entries, and kernel text and data are
 * mapped global on x86, so toggling CR4.PGE is the only way to flush everything.
 * Mirrors the kernel's own __native_flush_tlb_global(). */
static inline void local_flush_tlb_all(void)
{
    uint64_t cr4;
    asm volatile("movq %%cr4, %0" : "=r"(cr4));
    if (cr4 & (1ul << 7)) { /* CR4.PGE */
        asm volatile("movq %0, %%cr4" ::"r"(cr4 & ~(1ul << 7)) : "memory");
        asm volatile("movq %0, %%cr4" ::"r"(cr4) : "memory");
    } else {
        uint64_t cr3;
        asm volatile("movq %%cr3, %0" : "=r"(cr3));
        asm volatile("movq %0, %%cr3" ::"r"(cr3) : "memory");
    }
}

static inline void flush_tlb_all(void)
{
    local_flush_tlb_all();
}

static inline uint64_t tlbi_vaddr(uint64_t addr, uint64_t asid)
{
    (void)asid;
    return addr >> 12;
}

extern uint64_t kimage_voffset;
extern uint64_t linear_voffset;
extern uint64_t kernel_va;
extern uint64_t kernel_pa;
extern int64_t kernel_size;
extern int64_t page_shift;
extern int64_t page_size;
extern int64_t va_bits;
extern int64_t page_level;
extern uint64_t pgd_pa;
extern uint64_t pgd_va;

static inline uint64_t phys_to_virt(uint64_t phys)
{
    return phys + linear_voffset;
}

static inline uint64_t virt_to_phys(uint64_t virt)
{
    return virt - linear_voffset;
}

static inline uint64_t phys_to_kimg(uint64_t phys)
{
    return phys + kimage_voffset;
}

static inline uint64_t kimg_to_phys(uint64_t addr)
{
    return addr - kimage_voffset;
}

static inline int has_vmalloc_area(void)
{
    return kimage_voffset != linear_voffset;
}

static inline uint64_t kp_kimg_to_phys(uint64_t addr)
{
    return addr - kimage_voffset;
}

/* invlpg does invalidate global entries, so a per-page walk is correct here.
 * Bail out to a full flush for large ranges rather than loop over them. */
#define X86_TLB_SINGLE_PAGE_LIMIT 33

static inline void flush_tlb_kernel_range(uint64_t start, uint64_t end)
{
    if (end <= start) return;
    uint64_t first = start >> 12;
    uint64_t last = (end + 0xfff) >> 12;
    if (last - first > X86_TLB_SINGLE_PAGE_LIMIT) {
        local_flush_tlb_all();
        return;
    }
    for (uint64_t i = first; i < last; i++) asm volatile("invlpg (%0)" ::"r"(i << 12) : "memory");
}

static inline void flush_tlb_kernel_page(uint64_t addr)
{
    asm volatile("invlpg (%0)" :: "r"(addr) : "memory");
}

static inline int is_kimg_range(uint64_t addr)
{
    return addr >= kernel_va && addr < (kernel_va + kernel_size);
}

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);
uint64_t pgtable_phys(uint64_t pgd, uint64_t va);

static inline uint64_t *pgtable_entry_kernel(uint64_t va)
{
    return pgtable_entry(pgd_va, va);
}

static inline uint64_t pgtable_phys_kernel(uint64_t va)
{
    return pgtable_phys(pgd_va, va);
}

#else /* ARM64 */

#define MT_DEVICE_nGnRnE
#define MT_DEVICE_nGnRE
#define MT_DEVICE_GRE
#define MT_NORMAL_NC
#define MT_NORMAL
#define MT_NORMAL_WT

#define PTE_VALID (1ul << 0)
#define PTE_TYPE_MASK (3ul << 0)
#define PTE_TYPE_PAGE (3ul << 0)
#define PTE_TABLE_BIT (1ul << 1)
#define PTE_ATTRINDX(t) (t << 2) /* AttrIndx[2:0] encoding (mapping attributes defined in the MAIR_EL* registers */
#define PTE_NS (1ul << 5) /* Non-Secure access control */
#define PTE_USER (1ul << 6) /* AP[1] */
#define PTE_RDONLY (1ul << 7) /* AP[2] */
#define PTE_SHARED (3ul << 8) /* SH[1:0], inner shareable */
#define PTE_AF (1ul << 10) /* Access Flag */
#define PTE_NG (1ul << 11) /* nG */
#define PTE_GP (1ul << 50) /* BTI guarded */
#define PTE_DBM (1ul << 51) /* Dirty Bit Management */
#define PTE_CONT (1ul << 52) /* Contiguous range */
#define PTE_PXN (1ul << 53) /* Privileged XN */
#define PTE_UXN (1ul << 54) /* User XN */

#define PTE_WRITE (PTE_DBM) /* same as DBM (51) */
#define PTE_SWP_EXCLUSIVE (1ul << 2) /* only for swp ptes */
#define PTE_DIRTY (1ul << 55) /* software dirty in some version */
#define PTE_SPECIAL (1ul << 56)
#define PTE_DEVMAP (1ul << 57)
#define PTE_PROT_NONE (1ul << 58) /* only when !PTE_VALID */

#define PMD_PRESENT_INVALID (1ul << 59) /* only when !PMD_SECT_VALID */

#define PTATTR_PXN (1ul << 59)
#define PTATTR_XN (1ul << 60)
#define PTATTR_USER (1ul << 61) /* AP[1] read not premited in el0*/
#define PTATTR_RDONLY (1ul << 62) /* AP[2], write note permited at any exception level*/
#define PTATTR_NS (1ul << 63) /* Indicates whether the table identifier is located in Secure PA space */

#define pte_valid_cont(pte) (((pte) & (PTE_VALID | PTE_TABLE_BIT | PTE_CONT)) == (PTE_VALID | PTE_TABLE_BIT | PTE_CONT))

#define CONT_PTE_SHIFT (4 + page_shift)
#define CONT_PTES (1 << (CONT_PTE_SHIFT - page_shift))
#define CONT_PTE_SIZE (CONT_PTES * page_size)
#define CONT_PTE_MASK (~(CONT_PTE_SIZE - 1))

#define mask_ul(h, l) (((~0ul) << (l)) & (~0ul >> (63 - (h))))

#define sev() asm volatile("sev" : : : "memory")
#define wfe() asm volatile("wfe" : : : "memory")
#define wfi() asm volatile("wfi" : : : "memory")

#define isb() asm volatile("isb" : : : "memory")
#define dmb(opt) asm volatile("dmb " #opt : : : "memory")
#define dsb(opt) asm volatile("dsb " #opt : : : "memory")

#define tlbi_0(op)       \
    asm("tlbi " #op "\n" \
        "dsb ish\n"      \
        "tlbi " #op "\n")

#define tlbi_1(op, arg)      \
    asm("tlbi " #op ", %0\n" \
        "dsb ish\n"          \
        "tlbi " #op ", %0\n" \
        :                    \
        : "r"(arg))

static inline void local_flush_tlb_all(void)
{
    dsb(nshst);
    tlbi_0(vmalle1);
    dsb(nsh);
    isb();
}

static inline void flush_tlb_all(void)
{
    dsb(ishst);
    tlbi_0(vmalle1is);
    dsb(ish);
    isb();
}

// __TLBI_VADDR
static inline uint64_t tlbi_vaddr(uint64_t addr, uint64_t asid)
{
    uint64_t x = addr >> 12;
    x &= mask_ul(43, 0);
    x |= asid << 48;
    return x;
}

extern uint64_t kimage_voffset;
extern uint64_t linear_voffset;
extern uint64_t kernel_va;
extern uint64_t kernel_pa;
extern int64_t kernel_size;
extern int64_t page_shift;
extern int64_t page_size;
extern int64_t va_bits;
extern int64_t page_level;
extern uint64_t pgd_pa;
extern uint64_t pgd_va;
// extern int64_t pa_bits;

static inline uint64_t phys_to_virt(uint64_t phys)
{
    return phys + linear_voffset;
}

static inline uint64_t virt_to_phys(uint64_t virt)
{
    return virt - linear_voffset;
}

static inline uint64_t phys_to_kimg(uint64_t phys)
{
    return phys + kimage_voffset;
}

static inline uint64_t kimg_to_phys(uint64_t addr)
{
    return addr - kimage_voffset;
}

static inline int has_vmalloc_area()
{
    return kimage_voffset != linear_voffset;
}

static inline uint64_t kp_kimg_to_phys(uint64_t addr)
{
    return addr - kimage_voffset;
}

static inline void flush_tlb_kernel_range(uint64_t start, uint64_t end)
{
    start = tlbi_vaddr(start, 0);
    end = tlbi_vaddr(end, 0);
    dsb(ishst);
    for (uint64_t addr = start; addr < end; addr += 1 << (page_shift - 12))
        tlbi_1(vaale1is, addr);
    dsb(ish);
    isb();
}

static inline void flush_tlb_kernel_page(uint64_t addr)
{
    addr = tlbi_vaddr(addr, 0);
    dsb(ishst);
    tlbi_1(vaale1is, addr);
    dsb(ish);
    isb();
}

static inline int is_kimg_range(uint64_t addr)
{
    return addr >= kernel_va && addr < (kernel_va + kernel_size);
}

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);

static inline uint64_t *pgtable_entry_kernel(uint64_t va)
{
    return pgtable_entry(pgd_va, va);
}

uint64_t pgtable_phys(uint64_t pgd, uint64_t va);

static inline uint64_t pgtable_phys_kernel(uint64_t va)
{
    return pgtable_phys(pgd_va, va);
}

#endif /* CONFIG_X86_64 */

#endif