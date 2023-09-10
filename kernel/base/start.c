#include <common.h>
#include <pgtable.h>
#include <ktypes.h>
#include <kallsyms.h>
#include <log.h>
#include <compiler.h>
#include <init/init.h>
#include <cache.h>
#include <error.h>

#include "start.h"
#include "hook.h"

start_preset_t start_preset __attribute__((section(".start.data")));

int (*kallsyms_on_each_symbol)(int (*fn)(void *, const char *, struct module *, unsigned long), void *data) = 0;
unsigned long (*kallsyms_lookup_name)(const char *name) = 0;
int (*lookup_symbol_attrs)(unsigned long addr, unsigned long *size, unsigned long *offset, char *modname,
                           char *name) = 0;
void (*printk)(const char *fmt, ...) = 0;

uint32_t kver = 0;
uint32_t kpver = 0;
endian_t endian = little;

uint64_t kernel_va = 0;
uint64_t kernel_stext_va = 0;
uint64_t kernel_pa = 0;
int64_t kernel_size = 0;
uint64_t vabits_actual = 0;
int64_t memstart_addr = 0;
uint64_t kimage_voffset = 0;
uint64_t page_offset = 0;
int64_t page_shift = 0;
int64_t page_size = 0;
int64_t va_bits = 0;
// int64_t pa_bits = 0;

__noinline int pgtable_walk_kernel(uint64_t va, uint64_t *lv1, uint64_t *lv2, uint64_t *lv3)
{
    uint64_t page_level = (va_bits - 4) / (page_shift - 3);
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    uint64_t pxd_pa = ttbr1_el1 & ~0xfff;
    uint64_t pxd_va = phys_to_virt(pxd_pa);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;

    dsb(ishst);

    for (int64_t lv = 4 - page_level; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;

        dsb(ishst);

        if (!pxd_entry_va) {
            return ERR_PGTABLE;
        }
        if (lv == 1 && lv1)
            *lv1 = pxd_entry_va;
        if (lv == 2 && lv2)
            *lv2 = pxd_entry_va;
        if (lv == 3 && lv3)
            *lv3 = pxd_entry_va;

        dsb(ishst);

        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);
        dsb(ishst);
        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift)) - 1) << page_shift);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else { // invalid
            return ERR_ADDR;
        }
        dsb(ishst);
        pxd_va = phys_to_virt(pxd_pa);
        dsb(ishst);
        if (block_lv) {
            break;
        }
        dsb(ishst);
    }
#if 1
    uint64_t left_bit = page_shift + (block_lv ? (3 - block_lv) * pxd_bits : 0);
    uint64_t tpa = pxd_pa + (va & ((1u << left_bit) - 1));
    uint64_t tlva = phys_to_virt(tpa);
    uint64_t tkimg = phys_to_kimg(tpa);
    if (tlva != va && tkimg != va) {
        return ERR_PGTABLE;
    }
#endif
    dsb(ishst);
    // todo: ??????????
    printk("");
    return 0;
}

uint64_t *pgtable_entry_kernel(uint64_t va)
{
    uint64_t lv1 = 0, lv2 = 0, lv3 = 0;
    int rc = pgtable_walk_kernel(va, &lv1, &lv2, &lv3);
    if (rc)
        return 0;
    if (lv3)
        return (uint64_t *)lv3;
    if (lv2)
        return (uint64_t *)lv2;
    if (lv1)
        return (uint64_t *)lv1;
    // todo: ??????????
    printk("");
    return 0;
}

static __noinline int prot_myself()
{
    bool rdonly = true;
    bool dbm = true;
    uint64_t *kpte = pgtable_entry_kernel(kernel_stext_va);
    if (kpte) {
        rdonly = (*kpte & PTE_RDONLY) == PTE_RDONLY;
        dbm = (*kpte & PTE_DBM) == PTE_DBM;
    }

    // text, rodata
    uint64_t text_start = (uint64_t)_kp_text_start;
    uint64_t text_end = (uint64_t)_kp_text_end;
    uint64_t align_text_end = align_ceil(text_end, page_size);
    logkd("Text range: %llx, %llx\n", text_start, text_end);

    for (uint64_t i = text_start; i < align_text_end; i += page_size) {
        uint64_t lv1 = 0, lv2 = 0, lv3 = 0;
        int rc = pgtable_walk_kernel(i, &lv1, &lv2, &lv3);
        if (rc)
            return rc;

        *(uint64_t *)lv1 &= 0xF7FFFFFFFFFFFFFF;
        *(uint64_t *)lv2 &= 0xF7FFFFFFFFFFFFFF;

        uint64_t *pte = (uint64_t *)lv3;

        *pte |= PTE_SHARED;
        *pte = *pte & ~PTE_PXN & ~PTE_DBM & ~PTE_RDONLY;
        if (rdonly)
            *pte |= PTE_RDONLY;
        if (dbm)
            *pte |= PTE_DBM;
    }
    flush_tlb_kernel_range(text_start, align_text_end);

    // data, bss
    uint64_t data_start = (uint64_t)_kp_data_start;
    uint64_t data_end = (uint64_t)_kp_data_end;
    uint64_t align_data_end = align_ceil(data_end, page_size);
    logkd("Data range: %llx, %llx\n", data_start, data_end);

    for (uint64_t i = data_start; i < align_data_end; i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        if (!pte)
            return ERR_PGTABLE;
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_RDONLY;
    }
    flush_tlb_kernel_range(data_start, align_data_end);
    return 0;
}

static __noinline int restore_map()
{
    uint64_t start = kernel_va + start_preset.map_offset;
    uint64_t end = start + start_preset.map_backup_len;
    logkd("Restore range: %llx, %llx\n", start, end);

    for (uint64_t i = start; i < align_ceil(end, page_size); i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        if (!pte)
            return ERR_PGTABLE;
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
    return 0;
}

static __noinline int pgtable_init()
{
    uint64_t addr = kallsyms_lookup_name("memstart_addr");
    if (addr)
        memstart_addr = *(int64_t *)addr;
    addr = kallsyms_lookup_name("kimage_voffset");
    if (addr)
        kimage_voffset = *(uint64_t *)addr;
    addr = kallsyms_lookup_name("vabits_actual");
    if (addr)
        vabits_actual = *(uint64_t *)addr;

    uint64_t tcr_el1;
    asm("mrs %0, tcr_el1" : "=r"(tcr_el1));
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
    page_offset = vabits_actual ? -(1ul << va_bits) : (0xffffffffffffffff << (va_bits - 1));
    return 0;
}

static __noinline int hook_init()
{
    // rwx for hook
    for (uint32_t i = 0; i < HOOK_ALLOC_SIZE; i += (1 << page_shift)) {
        uint64_t va = (uint64_t)_kp_end + i;
        uint64_t lv1 = 0, lv2 = 0, lv3 = 0;
        int rc = pgtable_walk_kernel(va, &lv1, &lv2, &lv3);
        if (rc)
            return rc;
        *(uint64_t *)lv1 &= 0xF7FFFFFFFFFFFFFF;
        *(uint64_t *)lv2 &= 0xF7FFFFFFFFFFFFFF;
        uint64_t *pte = (uint64_t *)lv3;
        *pte = (*pte & ~PTE_PXN & ~PTE_RDONLY) | PTE_DBM | PTE_SHARED;
    }
    hook_mem_add((uint64_t)_kp_end, HOOK_ALLOC_SIZE);
    flush_tlb_kernel_range((uint64_t)_kp_end, (uint64_t)_kp_end + HOOK_ALLOC_SIZE);
    logkd("Hook range: %llx, %llx\n", (uint64_t)_kp_end, (uint64_t)_kp_end + HOOK_ALLOC_SIZE);
    return 0;
}

static __noinline int start_init(uint64_t kva)
{
    kernel_va = kva;
    kernel_pa = start_preset.kernel_pa;
    kernel_size = start_preset.kernel_size;
    uint64_t kallsym_addr = kva + start_preset.kallsyms_lookup_name_offset;
    kallsyms_lookup_name = (typeof(kallsyms_lookup_name))(kallsym_addr);
    kernel_stext_va = kallsyms_lookup_name("_stext");
    printk = (typeof(printk))kallsyms_lookup_name("printk");
    if (!printk) {
        printk = (typeof(printk))kallsyms_lookup_name("_printk");
    }

    endian = *(unsigned char *)&(uint16_t){ 1 } ? little : big;
    kver = VERSION(start_preset.kernel_version.major, start_preset.kernel_version.minor,
                   start_preset.kernel_version.patch);
    kpver = VERSION(start_preset.kp_version.major, start_preset.kp_version.minor, start_preset.kp_version.patch);
    logki("Kernel pa: %llx, va: %llx, size: %x\n", kernel_pa, kernel_va, start_preset.kernel_size);
    logki("Version: %x, Compile Time: %s\n", kpver, start_preset.compile_time);

    kallsyms_on_each_symbol = (typeof(kallsyms_on_each_symbol))kallsyms_lookup_name("kallsyms_on_each_symbol");
    lookup_symbol_attrs = (typeof(lookup_symbol_attrs))kallsyms_lookup_name("lookup_symbol_attrs");

    uint64_t scltr_el1 = 0;
    asm volatile("mrs %[reg], sctlr_el1" : [reg] "+r"(scltr_el1));
    logki("scltr_el1: %llx\n", scltr_el1);
    // asm volatile("bic %[reg], %[reg], #0x8000" : [reg] "+r"(scltr_el1));
    // asm volatile("msr sctlr_el1, %[reg]" : : [reg] "r"(scltr_el1));
    return 0;
}

static __noinline int nice_zone()
{
    logki("==== KernelPatch Entering Nicezone ====\n");
    // return init();
    return 0;
}

int __attribute__((section(".start.text"))) __noinline start(uint64_t kva)
{
    int err = 0;
    if ((err = start_init(kva)))
        goto out;
    if ((err = pgtable_init()))
        goto out;
    if ((err = prot_myself()))
        goto out;
    if ((err = restore_map()))
        goto out;
    if ((err = predata_init()))
        goto out;
    if ((err = hook_init()))
        goto out;

    if ((err = nice_zone()))
        goto out;
out:
    return err;
}
