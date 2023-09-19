#include "setup.h"

typedef uint64_t phys_addr_t;
typedef int (*memblock_reserve_f)(phys_addr_t base, phys_addr_t size);
typedef phys_addr_t (*memblock_phys_alloc_try_nid_f)(phys_addr_t size, phys_addr_t align, int nid);
typedef int (*memblock_mark_nomap_f)(phys_addr_t base, phys_addr_t size);
typedef int (*printk_f)(const char *fmt, ...);
typedef void (*paging_init_f)(void);

map_preset_t map_preset __section(.map.data) __aligned(MAP_ALIGN) = {
#ifdef MAP_DEBUG
    .str_fmt_px = "KP: %x-%llx\n",
#endif
};

uint64_t __section(.map.text) __noinline __aligned(MAP_ALIGN) get_myva()
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

static uint64_t get_kva()
{
    map_preset_t *preset = get_preset();
    uint64_t kernel_va = (uint64_t)preset - preset->map_offset;
    return kernel_va;
}

static uint64_t __noinline phys_to_lm(map_preset_t *preset, uint64_t phys)
{
    uint64_t page_offset = preset->page_offset;
    uint64_t virt = preset->kimage_voffset_relo ? (phys - preset->memstart_addr_relo) | page_offset :
                                                  phys - preset->memstart_addr_relo + page_offset;
    return virt;
}

// static uint64_t __noinline lm_to_phys(map_preset_t *preset, uint64_t virt)
// {
//     uint64_t page_offset = preset->page_offset;
//     uint64_t phys = preset->kimage_voffset_relo ? (virt & ~page_offset) + preset->memstart_addr_relo :
//                                                   virt - page_offset + preset->memstart_addr_relo;
//     return phys;
// }

static inline uint64_t phys_to_kimg(map_preset_t *preset, uint64_t phys)
{
    return phys + preset->kimage_voffset_relo;
}

static void flush_tlb_all()
{
    asm volatile("dsb ishst" : : : "memory");
    asm volatile("tlbi vmalle1is\n"
                 "dsb ish\n"
                 "tlbi vmalle1is\n");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static void flush_icache_all(void)
{
    asm volatile("dsb ish" : : : "memory");
    asm volatile("ic ialluis");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static map_preset_t *__noinline mem_proc()
{
    map_preset_t *preset = get_preset();
    uint64_t kernel_va = get_kva();
    preset->kernel_va = kernel_va;
    preset->paging_init_relo += kernel_va;
    preset->memblock_reserve_relo += kernel_va;
    preset->memblock_alloc_try_nid_relo += kernel_va;
    if (preset->memblock_mark_nomap_relo) {
        preset->memblock_mark_nomap_relo += kernel_va;
    }
    if (preset->memstart_addr_relo) {
        preset->memstart_addr_relo = *(int64_t *)(kernel_va + preset->memstart_addr_relo);
    }
    if (preset->kimage_voffset_relo) {
        preset->kimage_voffset_relo = *(uint64_t *)(kernel_va + preset->kimage_voffset_relo);
    }
#ifdef MAP_DEBUG
    preset->printk_relo += kernel_va;
#endif
    uint64_t tcr_el1;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    uint64_t t1sz = tcr_el1 << 42 >> 58; // bits(tcr_el1, 21, 16)
    uint64_t va1_bits = 64 - t1sz;
    preset->va1_bits = va1_bits;
    uint64_t tg1 = tcr_el1 << 32 >> 62; // bits(tcr_el1, 31, 30)
    uint64_t page_shift = 12;
    if (tg1 == 1) {
        page_shift = 14;
    }
    if (tg1 == 3) {
        page_shift = 16;
    }
    preset->page_shift = page_shift;
    preset->page_offset = preset->vabits_flag ? -(1ul << va1_bits) : (0xffffffffffffffff << (va1_bits - 1));
    return preset;
}

// todo: 52-bits pa
static uint64_t __noinline get_or_create_pte(map_preset_t *preset, uint64_t va, uint64_t pa)
{
#ifdef MAP_DEBUG
    printk_f printk = (printk_f)(preset->printk_relo);
#define map_debug(idx, val) printk(preset->str_fmt_px, idx, val)
#else
#define map_debug(idx, val)
#endif
    memblock_phys_alloc_try_nid_f memblock_phys_alloc_try_nid =
        (memblock_phys_alloc_try_nid_f)preset->memblock_alloc_try_nid_relo;
    uint64_t page_shift = preset->page_shift;
    uint64_t va_bits = preset->va1_bits;

    uint64_t page_level = (va_bits - 4) / (page_shift - 3);
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    uint64_t page_size = 1 << page_shift;
    uint64_t page_size_mask = ~(page_size - 1);
    uint64_t pxd_pa = ttbr1_el1 & page_size_mask;
    uint64_t pxd_va = phys_to_lm(preset, pxd_pa);
    uint64_t pxd_entry_va = 0;
    uint64_t block_flag = 0;
    uint64_t alloc_flag = 0;

    for (int64_t lv = 4 - page_level; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);

        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift)) - 1) << page_shift);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_flag = 1;
        } else { // invalid, alloc
            if (lv != 3) {
                pxd_pa = memblock_phys_alloc_try_nid(page_size, page_size, 0);
                alloc_flag = 1;
            } else {
                pxd_pa = pa;
                alloc_flag = 0;
            }
            uint64_t attr_prot = lv == 3 ? 0xC8000000000700 : 0x1000000000000000;
            pxd_desc = (pxd_pa) | 0b11 | attr_prot;
            *((uint64_t *)pxd_entry_va) = pxd_desc;
        }
        pxd_va = phys_to_lm(preset, pxd_pa);
        if (alloc_flag) {
            for (uint64_t i = pxd_va; i < pxd_va + page_size; i += 8) {
                *(uint64_t *)i = 0;
            }
        }
        if (block_flag) {
            break;
        }
    }
    return pxd_entry_va;
}

// todo: bti
void __noinline _paging_init()
{
    map_preset_t *preset = mem_proc();
#ifdef MAP_DEBUG
    printk_f printk = (printk_f)(preset->printk_relo);
#define map_debug(idx, val) printk(preset->str_fmt_px, idx, val)
#else
#define map_debug(idx, val)
#endif
    for (int i = 0; i < sizeof(map_preset_t); i += 8) {
        map_debug(i, *(uint64_t *)((uint64_t)preset + i));
    }
    // todo: memblock_free
    uint64_t old_start_pa = preset->start_offset + preset->kernel_pa;
    ((memblock_reserve_f)preset->memblock_reserve_relo)(old_start_pa, preset->start_size);

    phys_addr_t page_size = 1 << preset->page_shift;
    phys_addr_t start_size = (preset->start_size + page_size - 1) & ~(page_size - 1);
    phys_addr_t alloc_size = start_size + preset->alloc_size;

    uint64_t start_pa = ((memblock_phys_alloc_try_nid_f)preset->memblock_alloc_try_nid_relo)(alloc_size, page_size, 0);

    if (preset->kimage_voffset_relo && preset->memblock_mark_nomap_relo) {
        ((memblock_mark_nomap_f)(preset->memblock_reserve_relo))(start_pa, start_size);
    }

    // paging_init
    uint64_t paging_init_va = preset->paging_init_relo;
    *(uint32_t *)(paging_init_va) = preset->paging_init_backup;
    flush_icache_all();
    ((paging_init_f)(paging_init_va))();

    // clear wxn
    // todo: restore wxn later
    uint64_t sctlr_el1 = 0;
    asm volatile("mrs %[reg], sctlr_el1" : [reg] "+r"(sctlr_el1));
    sctlr_el1 &= 0xFFFFFFFFFFF7FFFF;
    asm volatile("msr sctlr_el1, %[reg]" : : [reg] "r"(sctlr_el1));
    asm volatile("isb");

    // start
    uint64_t old_start_va = phys_to_lm(preset, old_start_pa);
    // todo: random address
    // uint64_t vm_gurad_enough = page_size << 3;
    uint64_t offset = 0;
    uint64_t start_va = preset->kimage_voffset_relo ? phys_to_kimg(preset, start_pa) + offset :
                                                      phys_to_lm(preset, start_pa);
    for (uint64_t off = 0; off < alloc_size; off += page_size) {
        uint64_t entry = get_or_create_pte(preset, start_va + off, start_pa + off);
        *(uint64_t *)entry = (*(uint64_t *)entry | 0x8000000000000) & 0xFFDFFFFFFFFFFF7F;
    }
    flush_tlb_all();
    for (uint64_t i = 0; i < preset->start_size; i += 8) {
        *(uint64_t *)(start_va + i) = *(uint64_t *)(old_start_va + i);
    }
    flush_icache_all();

    // start
    ((start_f)start_va)(preset->kernel_va, offset);
}
