/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <common.h>
#include <pgtable.h>
#include <ktypes.h>
#include <kallsyms.h>
#include <compiler.h>
#include <cache.h>
#include <symbol.h>
#include <predata.h>
#include <barrier.h>
#include <stdarg.h>

#include "../banner"
#include "start.h"
#include "hook.h"
#include "tlsf.h"
#include "hmem.h"
#include "setup.h"

#define bits(n, high, low) (((n) << (63u - (high))) >> (63u - (high) + (low)))
#define align_floor(x, align) ((uint64_t)(x) & ~((uint64_t)(align) - 1))
#define align_ceil(x, align) (((uint64_t)(x) + (uint64_t)(align) - 1) & ~((uint64_t)(align) - 1))

start_preset_t start_preset __attribute__((section(".start.data")));

setup_header_t *setup_header = 0;
KP_EXPORT_SYMBOL(setup_header);

int (*kallsyms_on_each_symbol)(int (*fn)(void *data, const char *name, struct module *module, unsigned long addr),
                               void *data) = 0;
KP_EXPORT_SYMBOL(kallsyms_on_each_symbol);

unsigned long (*kallsyms_lookup_name)(const char *name) = 0;
KP_EXPORT_SYMBOL(kallsyms_lookup_name);

void (*printk)(const char *fmt, ...) = 0;
KP_EXPORT_SYMBOL(printk);

int (*vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);

static struct vm_struct
{
    struct vm_struct *next;
    void *addr;
    unsigned long size;
    unsigned long flags;
    struct page **pages;
#ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC
    unsigned int page_order;
#endif
    unsigned int nr_pages;
    phys_addr_t phys_addr;
    const void *caller;
} kp_vm = { 0 };

uint32_t kver = 0;
KP_EXPORT_SYMBOL(kver);

uint32_t kpver = 0;
KP_EXPORT_SYMBOL(kpver);

endian_t endian = little;
KP_EXPORT_SYMBOL(endian);

uint64_t _kp_extra_start = 0;
uint64_t _kp_extra_end = 0;
uint64_t _kp_hook_start = 0;
uint64_t _kp_hook_end = 0;
uint64_t _kp_rox_start = 0;
uint64_t _kp_rox_end = 0;
uint64_t _kp_rw_start = 0;
uint64_t _kp_rw_end = 0;
uint64_t _kp_region_start = 0;
uint64_t _kp_region_end = 0;

uint64_t link_base_addr = (uint64_t)_link_base;
uint64_t runtime_base_addr = 0;

uint64_t kimage_voffset = 0;
uint64_t linear_voffset = 0;
uint64_t kernel_va = 0;
uint64_t kernel_pa = 0;
int64_t kernel_size = 0;
int64_t page_shift = 0;
int64_t page_size = 0;
int64_t va_bits = 0;
int64_t page_level;
uint64_t pgd_pa;
uint64_t pgd_va;
// int64_t pa_bits = 0;

uint64_t kernel_stext_va = 0;

tlsf_t kp_rw_mem = 0;
tlsf_t kp_rox_mem = 0;

#define BOOT_LOG_SIZE 0x2000
static char boot_log[BOOT_LOG_SIZE] = { 0 };
static int boot_log_offset = 0;

static inline bool hw_dirty()
{
    uint64_t tcr_el1;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    return tcr_el1 & 0x10000000000;
}

const char *get_boot_log()
{
    return boot_log;
}

void log_boot(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    int ret = vsnprintf(boot_log + boot_log_offset, sizeof(boot_log) - boot_log_offset, fmt, va);
    va_end(va);
    printk("KP %s", boot_log + boot_log_offset);
    boot_log_offset += ret;
}

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys(pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;

    // ================
    // Branch to some function (even empty), It can work,
    // I don't know why, if anyone knows, please let me know. thank you very much.
    // ================
    __flush_dcache_area((void *)pxd_va, page_size);

    for (int64_t lv = 4 - page_level; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        if (!pxd_entry_va) return 0;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);
        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift)) - 1) << page_shift);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else { // invalid
            return 0;
        }
        //
        pxd_va = phys_to_virt(pxd_pa);
        if (block_lv) {
            break;
        }
    }
#if 0
    uint64_t left_bit = page_shift + (block_lv ? (3 - block_lv) * pxd_bits : 0);
    uint64_t tpa = pxd_pa + (va & ((1u << left_bit) - 1));
    uint64_t tlva = phys_to_virt(tpa);
    uint64_t tkimg = phys_to_kimg(tpa);
    if (tlva != va && tkimg != va) {
        return 0;
    }
#endif
    return (uint64_t *)pxd_entry_va;
}
KP_EXPORT_SYMBOL(pgtable_entry);

void modify_entry_kernel(uint64_t va, uint64_t *entry, uint64_t value)
{
    if (!pte_valid_cont(*entry) && !pte_valid_cont(value)) {
        *entry = value;
        flush_tlb_kernel_page(va);
        return;
    }

    uint64_t table_pa_mask = (((1ul << (48 - page_shift)) - 1) << page_shift);
    uint64_t prot = value & ~table_pa_mask;
    uint64_t *p = (uint64_t *)((uintptr_t)entry & ~(sizeof(entry) * CONT_PTES - 1));
    for (int i = 0; i < CONT_PTES; ++i, ++p)
        *p = (*p & table_pa_mask) | prot;

    *entry = value;
    va &= CONT_PTE_MASK;
    flush_tlb_kernel_range(va, va + CONT_PTES * page_size);
}

static void prot_myself()
{
    uint64_t *kpte = pgtable_entry_kernel(kernel_stext_va);
    log_boot("Kernel stext prot: %llx\n", *kpte);

    _kp_region_start = (uint64_t)_kp_text_start;
    _kp_region_end = (uint64_t)_kp_end + align_ceil(start_preset.extra_size, page_size) + HOOK_ALLOC_SIZE +
                     MEMORY_ROX_SIZE + MEMORY_RW_SIZE;
    log_boot("Region: %llx, %llx\n", _kp_region_start, _kp_region_end);

    uint64_t *kppte = pgtable_entry_kernel(_kp_region_start);
    log_boot("KernelPatch start prot: %llx\n", *kppte);

    // text, rodata
    uint64_t text_start = (uint64_t)_kp_text_start;
    uint64_t text_end = (uint64_t)_kp_text_end;
    uint64_t align_text_end = align_ceil(text_end, page_size);
    log_boot("Text: %llx, %llx\n", text_start, text_end);

    for (uint64_t i = text_start; i < align_text_end; i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_SHARED) & ~PTE_PXN & ~PTE_GP;
        if (has_vmalloc_area()) {
            *pte = (*pte | PTE_RDONLY) & ~PTE_DBM;
        }
    }
    flush_tlb_kernel_range(text_start, align_text_end);

    // data, bss
    uint64_t data_start = (uint64_t)_kp_data_start;
    uint64_t data_end = (uint64_t)_kp_data_end;
    uint64_t align_data_end = align_ceil(data_end, page_size);
    log_boot("Data: %llx, %llx\n", data_start, data_end);

    for (uint64_t i = data_start; i < align_data_end; i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_RDONLY;
        if (has_vmalloc_area()) {
            *pte |= PTE_PXN;
        }
    }
    flush_tlb_kernel_range(data_start, align_data_end);

    // extra data
    _kp_extra_start = (uint64_t)_kp_end;
    _kp_extra_end = _kp_extra_start + start_preset.extra_size;
    uint64_t align_extra_end = align_ceil(_kp_extra_end, page_size);
    log_boot("Extra: %llx, %llx\n", _kp_extra_start, _kp_extra_end);

    for (uint64_t i = _kp_extra_start; i < align_extra_end; i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_RDONLY;
        if (has_vmalloc_area()) {
            *pte |= PTE_PXN;
        }
    }
    flush_tlb_kernel_range(_kp_extra_start, align_extra_end);

    // rwx for hook
    _kp_hook_start = (uint64_t)align_extra_end;
    _kp_hook_end = _kp_hook_start + HOOK_ALLOC_SIZE;
    log_boot("Hook: %llx, %llx\n", _kp_hook_start, _kp_hook_end);

    for (uint64_t i = _kp_hook_start; i < _kp_hook_end; i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_PXN & ~PTE_RDONLY & ~PTE_GP;
    }
    flush_tlb_kernel_range(_kp_hook_start, _kp_hook_end);
    hook_mem_add(_kp_hook_start, HOOK_ALLOC_SIZE);

    // rw memory
    _kp_rw_start = _kp_hook_end;
    _kp_rw_end = _kp_rw_start + MEMORY_RW_SIZE;
    log_boot("RW: %llx, %llx\n", _kp_rw_start, _kp_rw_end);

    for (uint64_t i = _kp_rw_start; i < _kp_rw_end; i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_RDONLY;
        if (has_vmalloc_area()) {
            *pte |= PTE_PXN;
        }
    }
    flush_tlb_kernel_range(_kp_rw_start, _kp_rw_end);
    kp_rw_mem = tlsf_create_with_pool((void *)_kp_rw_start, MEMORY_RW_SIZE);

    // rox memory
    kp_rox_mem = tlsf_malloc(kp_rw_mem, tlsf_size());
    tlsf_create(kp_rox_mem);

    _kp_rox_start = _kp_rw_end;
    _kp_rox_end = _kp_rox_start + MEMORY_ROX_SIZE;
    log_boot("ROX: %llx, %llx\n", _kp_rox_start, _kp_rox_end);

    tlsf_add_pool(kp_rox_mem, (void *)_kp_rox_start, MEMORY_ROX_SIZE);

    for (uint64_t i = _kp_rox_start; i < _kp_rox_end; i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_SHARED) & ~PTE_PXN & ~PTE_GP;
        // todo: tlsf malloc block_split will write to alloced memory
        // if (has_vmalloc_area()) {
        // *pte |= PTE_RDONLY;
        // *pte &= ~PTE_DBM;
        // }
    }
    flush_tlb_kernel_range(_kp_rox_start, _kp_rox_end);

    // add to vmalloc area
    void (*vm_area_add_early)(struct vm_struct *vm) =
        (typeof(vm_area_add_early))kallsyms_lookup_name("vm_area_add_early");

    if (vm_area_add_early) {
        kp_vm.addr = (void *)_kp_region_start;
        kp_vm.phys_addr = kp_kimg_to_phys(_kp_region_start);
        kp_vm.size = _kp_region_end - _kp_region_start;
        kp_vm.flags = 0x00000044;
        kp_vm.caller = (void *)_kp_region_start;
        vm_area_add_early(&kp_vm);
        log_boot("add vmalloc area: %llx, %llx\n", kp_vm.addr, kp_vm.size);
    }
}

static void restore_map()
{
    uint64_t start = kernel_va + start_preset.map_offset;
    uint64_t end = start + start_preset.map_backup_len;
    log_boot("Restore: %llx, %llx\n", start, end);

    for (uint64_t i = start; i < align_ceil(end, page_size); i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        uint64_t orig = *pte;
        *pte = (orig | PTE_DBM) & ~PTE_RDONLY;
        flush_tlb_kernel_page(i);
        for (uint64_t j = i; j >= start && j < end && j < i + page_size; j += 8) {
            *(uint64_t *)j = *(uint64_t *)(start_preset.map_backup + (j - start));
        }
        *pte = orig;
        flush_tlb_kernel_page(i);
    }
    flush_icache_all();
}

#define log_reg(regname)                                                   \
    do {                                                                   \
        uint64_t regname##_val = 0;                                        \
        asm volatile("mrs %[val], " #regname : [val] "+r"(regname##_val)); \
        log_boot("" #regname ": %llx\n", regname##_val);                   \
    } while (0)

static void log_regs()
{
    // log_reg(APDAKey_EL1); //      | R/W [1] | Pointer Authentication Key A for Data (Hi/Lo pair)
    // log_reg(APDBKey_EL1); //      | R/W [1] | Pointer Authentication Key B for Data (Hi/Lo pair)
    // log_reg(APGAKey_EL1); //      | R/W [1] | Pointer Authentication Generic Key (Hi/Lo pair)
    // log_reg(APIAKey_EL1); //      | R/W [1] | Pointer Authentication Key A for Instructions (Hi/Lo pair)
    // log_reg(APIBKey_EL1); //      | R/W [1] | Pointer Authentication Key B for Instructions (Hi/Lo pair)
    // log_reg(CTR_EL0); //          | R   [5] | Cache Type Register
    // log_reg(HCR_EL2); //          | R   [2] | Hypervisor Configuration Register
    log_reg(ID_AA64AFR0_EL1); //  | R       | AArch64 Auxiliary Feature Register 0
    log_reg(ID_AA64AFR1_EL1); //  | R       | AArch64 Auxiliary Feature Register 1
    log_reg(ID_AA64DFR0_EL1); //  | R       | AArch64 Debug Feature Register 0
    log_reg(ID_AA64DFR1_EL1); //  | R       | AArch64 Debug Feature Register 1
    // log_reg(ID_AA64ISAR0_EL1); // | R       | AArch64 Instruction Set Attribute Register 0
    // log_reg(ID_AA64ISAR1_EL1); // | R       | AArch64 Instruction Set Attribute Register 1
    // log_reg(ID_AA64ISAR2_EL1); // | R       | AArch64 Instruction Set Attribute Register 2
    log_reg(ID_AA64MMFR0_EL1); // | R       | AArch64 Memory Model Feature Register 0
    log_reg(ID_AA64MMFR1_EL1); // | R       | AArch64 Memory Model Feature Register 1
    log_reg(ID_AA64MMFR2_EL1); // | R       | AArch64 Memory Model Feature Register 2
    // log_reg(ID_AA64MMFR3_EL1); // | R       | AArch64 Memory Model Feature Register 3
    // log_reg(ID_AA64MMFR4_EL1); // | R       | AArch64 Memory Model Feature Register 4
    log_reg(ID_AA64PFR0_EL1); //  | R       | AArch64 Processor Feature Register 0
    log_reg(ID_AA64PFR1_EL1); //  | R       | AArch64 Processor Feature Register 1
    // log_reg(ID_AA64PFR2_EL1); //  | R       | AArch64 Processor Feature Register 2
    // log_reg(ID_AA64SMFR0_EL1); // | R       | SME Feature ID register 0
    // log_reg(ID_AA64ZFR0_EL1); //  | R       | SVE Feature ID register 0
    log_reg(MAIR_EL1); //         | R       | Memory Attribute Indirection Register (EL1)
    // log_reg(MAIR2_EL1); //        | R       | Extended Memory Attribute Indirection Register (EL1)
    log_reg(MIDR_EL1); //         | R       | Main ID Register
    log_reg(MPIDR_EL1); //        | R       | Multiprocessor Affinity Register
    // log_reg(PIR_EL1); //          | R       | Permission Indirection Register 1 (EL1)
    // log_reg(PIRE0_EL1); //        | R       | Permission Indirection Register 0 (EL1)
    log_reg(REVIDR_EL1); //       | R       | Revision ID Register
    // log_reg(RNDR); //             | R       | Random Number
    // log_reg(RNDRRS); //           | R       | Reseeded Random Number
    // log_reg(SCR_EL3); //          |     [3] | Secure Configuration Register (EL3)
    log_reg(SCTLR_EL1); //        | R/W     | System Control Register (EL1)
    // log_reg(SCTLR2_EL1); //       | R/W     | System Control Register 2 (EL1)
    // log_reg(SCXTNUM_EL0); //      | R/W     | EL0 Read/Write Software Context Number
    // log_reg(SCXTNUM_EL1); //      | R/W     | EL1 Read/Write Software Context Number
    log_reg(TCR_EL1); //          | R       | Translation Control Register (EL1)
    // log_reg(TCR2_EL1); //         | R       | Extended Translation Control Register (EL1)
    // log_reg(TPIDR_EL0); //        | R/W [5] | EL0 Read/Write Software Thread ID Register
    // log_reg(TPIDR_EL1); //        | R/W [5] | EL1 Software Thread ID Register
    // log_reg(TPIDRRO_EL0); //      | R/W [5] | EL0 Read-Only Software Thread ID Register
    // log_reg(TRCDEVARCH); //       | R       | Trace Device Architecture Register
    log_reg(TTBR0_EL1); //        | R       | Translation Table Base Register 0 (EL1)
    log_reg(TTBR1_EL1); //        | R       | Translation Table Base Register 1 (EL1)
    // log_reg(PMMIR_EL1); //        | R       | Performance Monitors Machine Identification Register
    // log_reg(PMSIDR_EL1); //       | R   [4] | Sampling Profiling ID Register
}

static void start_init(uint64_t kimage_voff, uint64_t linear_voff)
{
    kimage_voffset = kimage_voff;
    linear_voffset = linear_voff;

    kernel_pa = start_preset.kernel_pa;
    kernel_va = kimage_voff + kernel_pa;
    kernel_size = start_preset.kernel_size;
    runtime_base_addr = (uint64_t)_link_base;

    uint64_t kallsym_addr = kernel_va + start_preset.kallsyms_lookup_name_offset;
    kallsyms_lookup_name = (typeof(kallsyms_lookup_name))(kallsym_addr);
    kernel_stext_va = kallsyms_lookup_name("_stext");
    printk = (typeof(printk))kallsyms_lookup_name("printk");
    if (!printk) printk = (typeof(printk))kallsyms_lookup_name("_printk");

    vsnprintf = (typeof(vsnprintf))kallsyms_lookup_name("vsnprintf");

    log_boot(KERNEL_PATCH_BANNER);

    endian = *(unsigned char *)&(uint16_t){ 1 } ? little : big;
    setup_header = &start_preset.header;
    kver = VERSION(start_preset.kernel_version.major, start_preset.kernel_version.minor,
                   start_preset.kernel_version.patch);
    kpver = VERSION(setup_header->kp_version.major, setup_header->kp_version.minor, setup_header->kp_version.patch);

    log_boot("Kernel pa: %llx\n", kernel_pa);
    log_boot("Kernel va: %llx\n", kernel_va);

    log_boot("Kernel Version: %x\n", kver);
    log_boot("KernelPatch Version: %x\n", kpver);
    log_boot("KernelPatch Config: %llx\n", setup_header->config_flags);
    log_boot("KernelPatch Compile Time: %s\n", (uint64_t)setup_header->compile_time);

    log_boot("KernelPatch link base: %llx, runtime base: %llx\n", link_base_addr, runtime_base_addr);

    kallsyms_on_each_symbol = (typeof(kallsyms_on_each_symbol))kallsyms_lookup_name("kallsyms_on_each_symbol");

    uint64_t tcr_el1;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    uint64_t t1sz = bits(tcr_el1, 21, 16);
    va_bits = 64 - t1sz;
    uint64_t tg1 = bits(tcr_el1, 31, 30);

    page_shift = 12;
    if (tg1 == 1) {
        page_shift = 14;
    } else if (tg1 == 3) {
        page_shift = 16;
    }
    page_size = 1 << page_shift;

    page_level = (va_bits - 4) / (page_shift - 3);

    uint64_t ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    uint64_t baddr = ttbr1_el1 & 0xFFFFFFFFFFFE;
    uint64_t page_size_mask = ~(page_size - 1);
    pgd_pa = baddr & page_size_mask;
    pgd_va = phys_to_virt(pgd_pa);
}

void symbol_init();
int patch();

int __attribute__((section(".start.text"))) __noinline start(uint64_t kimage_voff, uint64_t linear_voff)
{
    int rc = 0;
    start_init(kimage_voff, linear_voff);
    prot_myself();
    restore_map();
    log_regs();
    predata_init();
    symbol_init();
    rc = patch();
    return rc;
}
