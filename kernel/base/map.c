#include "setup.h"

typedef unsigned long phys_addr_t;
typedef unsigned long (*kallsyms_f)(const char *name);
typedef int (*memblock_reserve_f)(phys_addr_t base, phys_addr_t size);
typedef void *(*memblock_alloc_try_nid_f)(phys_addr_t size, phys_addr_t align, phys_addr_t min_addr,
                                          phys_addr_t max_addr, int nid);
typedef void (*printk_f)(const char *fmt, ...);
typedef void (*paging_init_f)(void);

map_preset_t map_preset __section(.map.data) __align(MAP_ALIGN) = {
#ifdef MAP_DEBUG
    .str_fmt_px = "KP:%2d - 0x%llx\n",
// .str_fmt_px = "KP:%2d - 0x%px\n",
#endif
};

uint64_t __section(.map.text) __noinline __align(MAP_ALIGN) get_myva()
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    return this_va & ~((uint64_t)MAP_ALIGN - 1);
}

map_preset_t *__noinline get_preset()
{
    uint64_t va = get_myva() - sizeof(map_preset_t);
    return (map_preset_t *)(va & ~((uint64_t)MAP_ALIGN - 1));
}

static inline uint64_t get_kva()
{
    map_preset_t *preset = get_preset();
    uint64_t kernel_va = (uint64_t)preset - preset->map_offset;
    return kernel_va;
}

static inline uint64_t phys_to_virt(map_preset_t *preset, uint64_t phys)
{
    uint64_t page_offset = preset->page_offset;
    uint64_t virt = preset->kimage_voffset_relo ? (phys - preset->memstart_addr_relo) | page_offset :
                                                  phys - preset->memstart_addr_relo + page_offset;
    return virt;
}

static inline uint64_t phys_to_kimg(map_preset_t *preset, uint64_t phys)
{
    return phys + preset->kimage_voffset_relo;
}

static uint64_t __noinline pa_to_va(map_preset_t *preset, uint64_t phys, uint32_t is_kimg)
{
    if (preset->kimage_voffset_relo && is_kimg) { return phys_to_kimg(preset, phys); }
    return phys_to_virt(preset, phys);
}

static inline void flush_tlb_all()
{
    asm volatile("dsb ishst" : : : "memory");
    asm volatile("tlbi vmalle1is\n"
                 "dsb ish\n"
                 "tlbi vmalle1is\n");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static inline void flush_icache_all(void)
{
    asm volatile("dsb ish" : : : "memory");
    asm volatile("ic ialluis");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

// todo: 52-bits pa
static uint64_t __noinline get_entry(uint64_t va, map_preset_t *preset, int32_t is_kimg)
{
    int32_t page_shift = preset->page_shift;
    int32_t va_bits = preset->va1_bits;
    uint32_t page_level = (va_bits - 4) / (page_shift - 3);
    uint32_t pxd_bits = page_shift - 3;
    uint32_t pxd_ptrs = 1u << pxd_bits;
    uint64_t ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    uint64_t pxd_pa = ttbr1_el1 & ~0xfff;
    uint64_t pxd_va = pa_to_va(preset, pxd_pa, is_kimg);
    uint64_t pxd_entry_va = 0;
    uint32_t block_flag = 0;
    for (int lv = 4 - page_level; lv < 4; lv++) {
        uint32_t pxd_shift = (page_shift - 3) * (4 - lv) + 3;
        uint32_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);
        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift)) - 1) << page_shift);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint32_t block_bits = (3 - lv) * pxd_bits + page_shift;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_flag = 1;
        } else { // invalid
            return (uint64_t)0;
        }
        pxd_va = pa_to_va(preset, pxd_pa, is_kimg);
        if (block_flag) { break; }
    }
    return pxd_entry_va;
}

static map_preset_t *__noinline mem_proc()
{
    map_preset_t *preset = get_preset();
    uint64_t kernel_va = get_kva();
    preset->kernel_va = kernel_va;

    preset->paging_init_relo += kernel_va;
    preset->memblock_reserve_relo += kernel_va;
    preset->memblock_alloc_try_nid_relo += kernel_va;

#ifdef MAP_DEBUG
    preset->kallsyms_lookup_name_relo += kernel_va;
    preset->printk_relo += kernel_va;
#endif

    if (preset->vabits_actual_relo) {
        preset->vabits_actual_relo = *(uint64_t *)(kernel_va + preset->vabits_actual_relo);
    }
    if (preset->memstart_addr_relo) {
        preset->memstart_addr_relo = *(int64_t *)(kernel_va + preset->memstart_addr_relo);
    }
    if (preset->kimage_voffset_relo) {
        preset->kimage_voffset_relo = *(uint64_t *)(kernel_va + preset->kimage_voffset_relo);
    }

    uint64_t tcr_el1;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    int32_t t1sz = tcr_el1 << 42 >> 58; // bits(tcr_el1, 21, 16)
    int32_t va1_bits = 64 - t1sz;
    preset->va1_bits = va1_bits;

    int32_t tg1 = tcr_el1 << 32 >> 62; // bits(tcr_el1, 31, 30)
    int32_t shift_map[] = { 12, 14, 12, 16 };
    int32_t page_shift = shift_map[tg1];
    preset->page_shift = page_shift;
    preset->page_offset = preset->vabits_actual_relo ? -(1ul << va1_bits) : (0xffffffffffffffff << (va1_bits - 1));
    return preset;
}

// void __noinline _start_kernel()
// {
// }

void __noinline _paging_init()
{
    map_preset_t *preset = mem_proc();

#ifdef MAP_DEBUG
    kallsyms_f kallsyms_lookup_name = (kallsyms_f)(preset->kallsyms_lookup_name_relo);
    printk_f printk = (printk_f)(preset->printk_relo);
#define map_debug(idx, val) printk(preset->str_fmt_px, idx, val)
    map_debug(0, kallsyms_lookup_name);
    map_debug(1, preset->tmp0);
#else
#define printk(fmt, ...)
#define kallsyms_lookup_name()
#define map_debug(idx, val)
#endif

#ifdef MAP_TRY_INLINE_HOOK
    ((paging_init_f)(preset->paging_init_relo_insts))();
    return;
#endif

    // todo: May cause memory wastage
    // ((memblock_reserve_f)preset->memblock_reserve_relo)(preset->start_offset + preset->kernel_pa, preset->start_size);

    // paging_init
    uint64_t paging_init_va = preset->paging_init_relo;
    uint64_t paging_init_entry = get_entry(paging_init_va, preset, 1);
    uint64_t paging_init_prot_ori = *(uint64_t *)paging_init_entry;
    *(uint64_t *)paging_init_entry = (paging_init_prot_ori | 0x0008000000000000) & 0xFFFFFFFFFFFFFF7F;
    flush_tlb_all();
    *(uint32_t *)(paging_init_va) = preset->paging_init_backup;
    flush_icache_all();
    *(uint64_t *)paging_init_entry = paging_init_prot_ori;
    flush_tlb_all();
    ((paging_init_f)(paging_init_va))();

    // start
    // uint64_t old_start = phys_to_virt(preset, preset->start_offset + preset->kernel_pa);
    // phys_addr_t page_size = 1 << preset->page_shift;
    // phys_addr_t start_size = (preset->start_size + page_size - 1) & ~(page_size - 1);
    // phys_addr_t alloc_size = start_size + preset->alloc_size;
    // uint64_t start =
    //     (uint64_t)((memblock_alloc_try_nid_f)preset->memblock_alloc_try_nid_relo)(alloc_size, page_size, 0, 0, -1);
    // if (!(start & 0xF000000000000000)) { start = phys_to_virt(preset, start); }
    // for (int32_t i = 0; i < preset->start_size; i += 4) { *(uint32_t *)(start + i) = *(uint32_t *)(old_start + i); }
    // flush_icache_all();
    // uint64_t start_entry = get_entry(start, preset, 0);
    // *(uint64_t *)start_entry &= 0xFFDFFFFFFFFFFFFF;
    // flush_tlb_all();
    // ((start_f)start)(preset->kernel_pa, preset->kernel_va);
}
