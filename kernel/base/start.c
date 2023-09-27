#include <common.h>
#include <pgtable.h>
#include <ktypes.h>
#include <kallsyms.h>
#include <compiler.h>
#include <init/init.h>
#include <cache.h>
#include <error.h>

#include "start.h"
#include "hook.h"

start_preset_t start_preset __attribute__((section(".start.data")));

int (*kallsyms_on_each_symbol)(int (*fn)(void *data, const char *name, struct module *module, unsigned long addr),
                               void *data) = 0;
unsigned long (*kallsyms_lookup_name)(const char *name) = 0;
int (*lookup_symbol_attrs)(unsigned long addr, unsigned long *size, unsigned long *offset, char *modname,
                           char *name) = 0;
void (*printk)(const char *fmt, ...) = 0;

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
uint32_t kpver = 0;
endian_t endian = little;

uint64_t kernel_va = 0;
uint64_t kernel_stext_va = 0;
uint64_t kernel_pa = 0;
int64_t kernel_size = 0;
int64_t vabits_flag = 0;
int64_t memstart_addr = 0;
uint64_t kimage_voffset = 0;
uint64_t page_offset = 0;
int64_t page_shift = 0;
int64_t page_size = 0;
int64_t va_bits = 0;
uint64_t kp_kimg_offset = 0;
// int64_t pa_bits = 0;

uint64_t *pgtable_entry_kernel(uint64_t va)
{
    uint64_t page_level = (va_bits - 4) / (page_shift - 3);
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    uint64_t page_size = 1 << page_shift;
    uint64_t page_size_mask = ~(page_size - 1);
    uint64_t pxd_pa = ttbr1_el1 & page_size_mask;

    uint64_t pxd_va = phys_to_virt(pxd_pa);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;

    for (int64_t lv = 4 - page_level; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;

        if (!pxd_entry_va) {
            return 0;
        }
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
        dsb(ishst);
        pxd_va = phys_to_virt(pxd_pa);
        if (block_lv) {
            break;
        }
    }
#if 1
    uint64_t left_bit = page_shift + (block_lv ? (3 - block_lv) * pxd_bits : 0);
    uint64_t tpa = pxd_pa + (va & ((1u << left_bit) - 1));
    uint64_t tlva = phys_to_virt(tpa);
    uint64_t tkimg = phys_to_kimg(tpa);
    if (tlva != va && tkimg != va) {
        return 0;
    }
#endif
    // todo: some cache ???????????
    // printk("pgtable va: %llx, entry: %llx, desc: %llx\n", va, pxd_entry_va, *(uint64_t *)pxd_entry_va);
    printk("");
    return (uint64_t *)pxd_entry_va;
}

static __noinline int prot_myself()
{
    // text, rodata
    uint64_t text_start = (uint64_t)_kp_text_start;
    uint64_t text_end = (uint64_t)_kp_text_end;
    uint64_t align_text_end = align_ceil(text_end, page_size);
    printk("KP Text start: %llx\n", text_start);
    printk("KP Text end: %llx\n", text_end);

    for (uint64_t i = text_start; i < align_text_end; i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        if (!pte)
            return ERR_PGTABLE;
        *pte |= PTE_SHARED;
        *pte = *pte & ~PTE_PXN;
        if (kimage_voffset) {
            *pte |= PTE_RDONLY;
            *pte &= ~PTE_DBM;
        }
    }
    flush_tlb_kernel_range(text_start, align_text_end);

    // data, bss
    uint64_t data_start = (uint64_t)_kp_data_start;
    uint64_t data_end = (uint64_t)_kp_data_end;
    uint64_t align_data_end = align_ceil(data_end, page_size);
    printk("KP Data start: %llx\n", data_start);
    printk("KP Data end: %llx\n", data_end);

    for (uint64_t i = data_start; i < align_data_end; i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        if (!pte)
            return ERR_PGTABLE;
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_RDONLY;
        if (kimage_voffset) {
            *pte |= PTE_PXN;
        }
    }
    flush_tlb_kernel_range(data_start, align_data_end);

    // rwx for hook
    // todo: w when needed
    uint64_t hook_start = (uint64_t)_kp_end;
    uint64_t hook_end = hook_start + HOOK_ALLOC_SIZE;
    printk("KP Hook start: %llx\n", hook_start);
    printk("KP Hook end: %llx\n", hook_end);

    for (uint64_t i = hook_start; i < hook_end; i += page_size) {
        uint64_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte & ~PTE_PXN & ~PTE_RDONLY) | PTE_DBM | PTE_SHARED;
    }
    flush_tlb_kernel_range(hook_start, hook_end);
    hook_mem_add(hook_start, HOOK_ALLOC_SIZE);

    // add to vmalloc area
    if (kimage_voffset) {
        printk("KP Add to vmalloc area\n");
        void (*vm_area_add_early)(struct vm_struct *vm) =
            (typeof(vm_area_add_early))kallsyms_lookup_name("vm_area_add_early");
        kp_vm.addr = (void *)text_start;
        kp_vm.phys_addr = kp_kimg_to_phys(text_start);
        kp_vm.size = hook_end - text_start;
        kp_vm.flags = 0x00000044;
        kp_vm.caller = (void *)text_start;
        vm_area_add_early(&kp_vm);
    }
    return 0;
}

static __noinline int restore_map()
{
    uint64_t start = kernel_va + start_preset.map_offset;
    uint64_t end = start + start_preset.map_backup_len;
    printk("KP Restore start: %llx\n", start);
    printk("KP Restore end: %llx\n", end);

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
    if (addr) {
        memstart_addr = *(int64_t *)addr;
    }
    addr = kallsyms_lookup_name("kimage_voffset");
    if (addr) {
        kimage_voffset = *(uint64_t *)addr;
    }
    addr = kallsyms_lookup_name("vabits_actual");
    if (addr) {
        vabits_flag = 1;
    }
    if (kver >= VERSION(6, 0, 0)) {
        vabits_flag = 1;
    }

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
    page_offset = vabits_flag ? -(1ul << va_bits) : (0xffffffffffffffff << (va_bits - 1));

    return 0;
}

#define log_reg(regname)                                                   \
    do {                                                                   \
        uint64_t regname##_val = 0;                                        \
        asm volatile("mrs %[val], " #regname : [val] "+r"(regname##_val)); \
        printk("KP " #regname ": %llx\n", regname##_val);                  \
    } while (0)

static __noinline void log_regs()
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

static __noinline int start_init(uint64_t kva, uint64_t offset)
{
    kernel_va = kva;
    kp_kimg_offset = offset;
    kernel_pa = start_preset.kernel_pa;
    kernel_size = start_preset.kernel_size;
    uint64_t kallsym_addr = kva + start_preset.kallsyms_lookup_name_offset;
    kallsyms_lookup_name = (typeof(kallsyms_lookup_name))(kallsym_addr);
    kernel_stext_va = kallsyms_lookup_name("_stext");
    printk = (typeof(printk))kallsyms_lookup_name("printk");
    if (!printk) {
        printk = (typeof(printk))kallsyms_lookup_name("_printk");
    }
    if (!printk) {
        return ERR_NO_SUCH_SYMBOL;
    }

    endian = *(unsigned char *)&(uint16_t){ 1 } ? little : big;
    kver = VERSION(start_preset.kernel_version.major, start_preset.kernel_version.minor,
                   start_preset.kernel_version.patch);
    kpver = VERSION(start_preset.kp_version.major, start_preset.kp_version.minor, start_preset.kp_version.patch);
    // todo: ?? In some case, (ranchu, api28, 4.4.302, api29, 4.14.175), sometimes, format string (%xx) cause "BUG: recent printk recursion!"
    printk("KP Kernel pa: %llx\n", kernel_pa);
    printk("KP Kernel va: %llx\n", kernel_va);
    printk("KP Kernel Patch Version: %x\n", kpver);
    printk("KP Kernel Patch Compile Time: %s\n", start_preset.compile_time);

    kallsyms_on_each_symbol = (typeof(kallsyms_on_each_symbol))kallsyms_lookup_name("kallsyms_on_each_symbol");
    lookup_symbol_attrs = (typeof(lookup_symbol_attrs))kallsyms_lookup_name("lookup_symbol_attrs");

    return 0;
}

static __noinline int nice_zone()
{
    printk("KP ==== KernelPatch Entering Nicezone ====\n");
    return init();
}

int __attribute__((section(".start.text"))) __noinline start(uint64_t kva, uint64_t offset)
{
    int err = 0;
    if ((err = start_init(kva, offset)))
        goto out;
    log_regs();
    if ((err = pgtable_init()))
        goto out;
    if ((err = prot_myself()))
        goto out;
    if ((err = restore_map()))
        goto out;
    if ((err = predata_init()))
        goto out;

    if ((err = nice_zone()))
        goto out;
out:
    return err;
}
