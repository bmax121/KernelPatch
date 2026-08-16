/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <hotpatch.h>
#include <cache.h>
#include <ksyms.h>
#include <symbol.h>
#include <pgtable.h>
#include <asm/atomic.h>
#include <linux/cpumask.h>
#include <linux/vmalloc.h>
#include <linux/stop_machine.h>
#include <uapi/asm-generic/errno.h>

static uintptr_t table_pa_mask = 0;

static void *alias_page = 0;
static uintptr_t *alias_entry = 0;
static uintptr_t alias_pte = 0;

int kfunc_def(aarch64_insn_patch_text_nosync)(void *addr, uint32_t insn) = 0;

static void modify_entry_kernel(uintptr_t va, uintptr_t *entry, uintptr_t value)
{
    if (!pte_valid_cont(*entry) && !pte_valid_cont(value)) {
        *entry = value;
        flush_tlb_kernel_page(va);
        return;
    }

    uintptr_t prot = value & ~table_pa_mask;
    uintptr_t *p = (uintptr_t *)((uintptr_t)entry & ~(sizeof(entry) * CONT_PTES - 1));
    for (int i = 0; i < CONT_PTES; ++i, ++p) {
        *p = (*p & table_pa_mask) | prot;
    }

    *entry = value;
    va &= CONT_PTE_MASK;
    flush_tlb_kernel_range(va, va + CONT_PTES * page_size);
}

int hotpatch_nosync(void *addr, uint32_t value)
{
    uintptr_t tp = (uintptr_t)addr;
    if (tp & 0x3) return -EINVAL;
    if (kfunc(aarch64_insn_patch_text_nosync) && alias_pte) {
        // todo: fixmap
        uintptr_t phys = pgtable_phys_kernel(tp);
        if (!phys) return -EFAULT;
        *alias_entry = (alias_pte & ~table_pa_mask) | (phys & ~(page_size - 1));
        dsb(ish);
        void *alias_addr = alias_page + (tp & (page_size - 1));
        int rc = kfunc(aarch64_insn_patch_text_nosync)(alias_addr, value);
        *alias_entry = alias_pte;
        dsb(ish);
        if (!rc) return rc;
    }
    uintptr_t *entry = pgtable_entry_kernel(tp);
    if (!entry) return -EFAULT;
    uintptr_t ori_prot = *entry;
    modify_entry_kernel(tp, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
    *(uint32_t *)tp = value;
    modify_entry_kernel(tp, entry, ori_prot);
    flush_icache_all();
    return 0;
}
KP_EXPORT_SYMBOL(hotpatch_nosync);

struct hotpatch_t
{
    void **addrs;
    u32 *values;
    int cnt;
    atomic_t index;
};

static int hotpatch_cb(void *arg)
{
    int i, ret = 0;
    struct hotpatch_t *pp = arg;
    int index = atomic_inc_return(&pp->index);
    if (!index || index == num_online_cpus()) {
        for (i = 0; ret == 0 && i < pp->cnt; ++i)
            ret = hotpatch_nosync(pp->addrs[i], pp->values[i]);

        atomic_inc(&pp->index);
    } else {
        while (atomic_read(&pp->index) <= num_online_cpus())
            asm volatile("yield" ::: "memory");

        isb();
    }
    return ret;
}

static inline int is_interrupt_masked()
{
    unsigned long daif;
    asm volatile("mrs %0, daif" : "=r"(daif));
    // https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/DAIF--Interrupt-Mask-Bits
    return daif & 0xC0;
}

int hotpatch(void *addrs[], uint32_t values[], int cnt)
{
    struct hotpatch_t patch = {
        .addrs = addrs,
        .values = values,
        .cnt = cnt,
        .index = ATOMIC_INIT(0),
    };
    if (cnt <= 0) return -EINVAL;
    if (!kfunc(stop_machine) || is_interrupt_masked() || !cpu_online_mask || !kvar(nr_cpu_ids) ||
        num_online_cpus() == 1) {
        atomic_dec_return(&patch.index);
        return hotpatch_cb(&patch);
    }
    return stop_machine(hotpatch_cb, &patch, cpu_online_mask);
}
KP_EXPORT_SYMBOL(hotpatch);

static void _arch_arm64_text_patching_init(const char *name, unsigned long addr)
{
    kfunc_match(aarch64_insn_patch_text_nosync, name, addr);
}

static int _hotpatch_symbol_init(void *data, const char *name, struct module *m, unsigned long addr)
{
    _arch_arm64_text_patching_init(name, addr);
    return 0;
}

void hotpatch_symbol_init()
{
#ifdef INIT_USE_KALLSYMS_LOOKUP_NAME
    _hotpatch_symbol_init(0, 0, 0, 0);
#else
    kallsyms_on_each_symbol(_hotpatch_symbol_init, 0);
#endif

    table_pa_mask = (((1ul << (48 - page_shift)) - 1) << page_shift);
}

int hotpatch_init()
{
    alias_page = vmalloc(page_size);
    if (alias_page) {
        alias_entry = pgtable_entry_kernel((uintptr_t)alias_page);
        if (alias_entry) alias_pte = *alias_entry;
    }
    log_boot("alias_page: %llx\n", alias_page);
    log_boot("alias_pte: %llx\n", alias_pte);
    return 0;
}
