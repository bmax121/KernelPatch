#ifndef _KP_SETUP_H_
#define _KP_SETUP_H_

#include "./preset.h"

#define HOOK_ALLOC_SIZE (256 * 1024)
#define STACK_SIZE 2048
#define MAP_MAX_SIZE 0xa00
#define MAP_ALIGN 16

#ifndef __ASSEMBLY__

#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)

#define __section(s) __attribute__((section(#s)))
#define __noinline __attribute__((__noinline__))
#define __aligned(x) __attribute__((aligned(x)))

#endif

#ifndef __ASSEMBLY__
typedef struct
{
    // preset
    int32_t map_offset;
    uint32_t paging_init_backup;
    int32_t start_offset;
    int32_t start_size;
    int32_t alloc_size;
    int32_t __;
    uint64_t kernel_pa;
    uint64_t paging_init_relo;
    uint64_t memblock_reserve_relo;
    uint64_t memblock_alloc_try_nid_relo;
    uint64_t vabits_actual_relo;
    int64_t memstart_addr_relo;
    uint64_t kimage_voffset_relo;
#ifdef MAP_DEBUG
    uint64_t printk_relo;
    uint64_t kallsyms_lookup_name_relo;
    uint64_t tmp0;
    uint64_t tmp1;
    char str_fmt_px[24];
#endif
    // local
    int32_t va1_bits;
    int32_t page_shift;
    uint64_t kernel_va;
    uint64_t page_offset;
} map_preset_t;
#else
#define map_map_offset_offset 0
#define map_paging_init_backup_offset 4
#define map_start_offset_offset 8
#define map_start_size_offset 0xc
#define map_alloc_size_offset 0x10
#define map_kernel_pa_offset 0x18
#define map_paging_init_relo_offset 0x20
#define map_memblock_reserve_relo_offset 0x28
#define map_memblock_alloc_try_nid_relo_offset 0x30
#define map_vabits_actual_relo_offset 0x38
#define map_memstart_addr_relo_offset 0x40
#define map_kimage_voffset_relo_offset 0x48
#ifdef MAP_DEBUG
#define map_printk_relo_offset 0x50
#define map_kallsyms_lookup_name_relo_offset 0x58
#define map_tmp0_offset 0x60
#define map_tmp1_offset 0x68
#define map_str_fmt_px_offset 0x70
#endif // MAP_DEBUG
#endif

#ifndef __ASSEMBLY__
typedef int (*start_f)(uint64_t kpa, uint64_t kva);
extern void _start_kernel();
extern void _paging_init();
extern void _link_base();
extern void _link_end();
extern void _setup_start();
extern void _setup_end();
extern void _map_start();
extern void _map_text();
extern void _map_data();
extern void _map_end();
extern void _kp_end();
#endif // __ASSEMBLY__

#endif // _KP_SETUP_H_