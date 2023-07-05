#ifndef _KP_SETUP_H_
#define _KP_SETUP_H_

#include "../preset/preset.h"

// #define MAP_TRY_INLINE_HOOK

#define HOOK_ALLOC_SIZE (256 * 1024)
#define STACK_SIZE 2048
#define MAP_MAX_SIZE 0xa00
#define MAP_ALIGN 16

#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)

#define __section(s) __attribute__((section(#s)))
#define __noinline __attribute__((__noinline__))
#define __align(x) __attribute__((aligned(x)))

typedef struct
{
    uint32_t paging_init_backup;
#ifdef MAP_TRY_INLINE_HOOK
    int32_t paging_init_relo_insts[2];
#endif
    int32_t map_offset;
    int32_t start_offset;
    int32_t start_size;
    int32_t alloc_size;
    uint64_t kernel_pa;

    uint64_t paging_init_relo;
    uint64_t memblock_reserve_relo;
    uint64_t memblock_alloc_try_nid_relo;
    uint64_t vabits_actual_relo;
    int64_t memstart_addr_relo;
    uint64_t kimage_voffset_relo;

    int32_t va1_bits;
    int32_t page_shift;
    uint64_t kernel_va;
    uint64_t page_offset;

#ifdef MAP_DEBUG
    uint64_t printk_relo;
    uint64_t kallsyms_lookup_name_relo;
    uint64_t tmp0;
    char str_fmt_px[20];
#endif
} map_preset_t;

typedef int (*start_f)(uint64_t kpa, uint64_t kva);

void _start_kernel();
void _paging_init();

void _link_base();
void _link_end();

void _setup_start();
void _setup_end();

void _map_start();
void _map_text();
void _map_data();
void _map_end();

void _kp_end();

#endif