#include "setup.h"
#include "start.h"
#include "../version"

extern map_preset_t map_preset;
extern start_preset_t start_preset;

setup_header_t header __section(.setup.header) = { .magic = "KP1158",
                                                   .kp_version.major = MAJOR,
                                                   .kp_version.minor = MINOR,
                                                   .kp_version.patch = PATCH,
                                                   .compile_time = __TIME__ " " __DATE__ };

setup_preset_t setup_preset __section(.setup.preset) = { 0 };

// static uint64_t kernel_pa __section(.setup.data) = 0;

struct
{
    uint8_t fp[STACK_SIZE];
    uint8_t sp[0];
} stack __section(.setup.data) __aligned(16);

#define B_REL(src, dst) (0x14000000u | (((dst - src) & 0x0FFFFFFFu) >> 2u))
#define BL_REL(src, dst) (0x94000000u | (((dst - src) & 0x0FFFFFFFu) >> 2u))

// void __noinline rmemcpy32(uint64_t dst, uint64_t src, int64_t size)
// {
//     for (int32_t i = size - 4; i >= 0; i -= 4) *(uint32_t *)(dst + i) = *(uint32_t *)(src + i);
// }

// static void __noinline start_prepare()
// {
//     // backup map occupied area
//     uint64_t map_pa = kernel_pa + preset.map_offset;
//     int64_t map_size = (int64_t)(_map_end - _map_start);
//     start_preset.kernel_size = preset.kernel_size;
//     start_preset.kallsyms_lookup_name_offset = preset.kallsyms_lookup_name_offset;
//     start_preset.map_offset = preset.map_offset;
//     start_preset.map_backup_len = map_size;
//     memcpy32((uint64_t)start_preset.map_backup, map_pa, map_size);

//     // start_preset
//     start_preset.kernel_version = preset.kernel_version;
//     start_preset.kp_version = header.kp_version;
//     memcpy32((uint64_t)start_preset.superkey, (uint64_t)preset.superkey, SUPER_KEY_LEN);
//     memcpy32((uint64_t)start_preset.compile_time, (uint64_t)header.compile_time, SUPER_KEY_LEN);

//     // move start
//     uint64_t from = (uint64_t)_kp_start;
//     int64_t start_size = (int64_t)(_kp_end - _kp_start);
//     int32_t start_offset = preset.kernel_size;

//     uint32_t version_code =
//         (uint32_t)VERSION(preset.kernel_version.major, preset.kernel_version.minor, preset.kernel_version.patch);
//     if (version_code >= VERSION(4, 13, 0)) start_offset += (1 << preset.page_shift); // vm guard page

//     uint64_t to = kernel_pa + start_offset;

//     memcpy32(to, from, start_size);

//     map_preset.start_offset = start_offset;
//     map_preset.start_size = start_size;
//     map_preset.alloc_size = HOOK_ALLOC_SIZE;
// }

// void __noinline map_prepare1(uint64_t kernel_pa)
// {
//     int32_t map_offset = preset.map_offset;
//     map_preset.kernel_pa = kernel_pa;
//     map_preset.map_offset = map_offset;

//     map_preset.paging_init_relo = preset.paging_init_offset;
//     map_preset.memblock_reserve_relo = preset.memblock_reserve_offset;
//     map_preset.memblock_alloc_try_nid_relo = preset.memblock_alloc_try_nid_offset;

//     map_preset.vabits_actual_relo = preset.vabits_actual_offset < 0 ? 0 : preset.vabits_actual_offset;
//     map_preset.memstart_addr_relo = preset.memstart_addr_offset < 0 ? 0 : preset.memstart_addr_offset;
//     map_preset.kimage_voffset_relo = preset.kimage_voffset_offset < 0 ? 0 : preset.kimage_voffset_offset;

// #ifdef MAP_DEBUG
//     map_preset.printk_relo = preset.printk_offset;
//     map_preset.kallsyms_lookup_name_relo = preset.kallsyms_lookup_name_offset;
// #endif

//     // paging_init
//     uint64_t paging_init_offset = preset.paging_init_offset;
//     uint32_t paging_init_inst = *(uint32_t *)(paging_init_pa);
//     uint64_t paging_init_pa = paging_init_offset + kernel_pa;

//     map_preset.paging_init_backup = paging_init_inst;
//     uint64_t replace_pa = (uint64_t)(_paging_init - _map_start) + map_offset + kernel_pa;
//     // replace
//     *(uint32_t *)paging_init_pa = B_REL(paging_init_pa, replace_pa);

//     // move map
//     int64_t size = (int64_t)(_map_end - _map_start);
//     uint64_t from = (uint64_t)_map_start;
//     uint64_t to = preset.map_offset + kernel_pa;
//     rmemcpy32(to, from, size);
// }

// void __noinline setup(void *fdtp, void *r1, void *r2, void *r3)
// {
//     kernel_pa = (uint64_t)_link_base - preset.kp_offset;

//     // start_prepare();
//     map_prepare(kernel_pa);

//     memcpy32(kernel_pa, (uint64_t)preset.header_backup, sizeof(preset.header_backup));

//     // I-cache maybe on
//     asm volatile("dsb ish" : : : "memory");
//     asm volatile("ic iallu");
//     asm volatile("isb" : : : "memory");

//     void (*head)(void *, void *, void *, void *) = 0;
//     head = (typeof(head))(kernel_pa);
//     head(fdtp, r1, r2, r3);
// }

// arm64 not support  __attribute__((naked))
// x0 = physical address to the FDT blob.
// void __section(.setup.text) setup_entry(void *fdtp, void *r1, void *r2, void *r3)
// {
//     asm volatile("nop");
//     asm volatile("nop");
//     asm volatile("nop");
//     asm volatile("nop");
//     // make sure not use stack here
//     uint64_t sp = (uint64_t)&stack.sp;
//     asm volatile("mov sp, %0" ::"r"(sp));
//     // now we can use stack
//     setup(fdtp, r1, r2, r3);
// }
