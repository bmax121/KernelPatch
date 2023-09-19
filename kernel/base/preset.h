#ifndef _KP_PRESET_H_
#define _KP_PRESET_H_

#ifndef __ASSEMBLY__
#include <stdint.h>
#endif

#define MAGIC_LEN 0x8
#define KP_HEADER_SIZE 0x40
#define SUPER_KEY_LEN 0x40
#define HDR_BACKUP_SIZE 0x8
#define COMPILE_TIME_LEN 0x18
#define MAP_MAX_SIZE 0xa00
#define HOOK_ALLOC_SIZE (256 * 1024)
#define MAP_ALIGN 16

#define VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))

#ifndef __ASSEMBLY__
typedef struct version_t
{
    uint8_t _;
    uint8_t patch;
    uint8_t minor;
    uint8_t major;
} version_t;
#endif

#ifndef __ASSEMBLY__
typedef struct _setup_header_t // 64-bytes
{
    char magic[MAGIC_LEN];
    version_t kp_version;
    version_t kernel_version;
    char compile_time[COMPILE_TIME_LEN];
    char _reserved[];
} setup_header_t;
#else
#define header_magic_offset 0
#define header_kp_version_offset (MAGIC_LEN)
#define header_kernel_version_offset (header_kp_version_offset + 4)
#define header_compile_time_offset (header_kernel_version_offset + 4)
#endif

#ifndef __ASSEMBLY__
typedef struct _setup_preset_t
{
    int64_t kernel_size;
    int64_t page_shift;
    int64_t kp_offset;
    int64_t start_offset;
    int64_t map_offset; // must aligned MAP_ALIGN
    int64_t map_max_size;

    int64_t kallsyms_lookup_name_offset;
    int64_t paging_init_offset;
    int64_t printk_offset;
    int64_t memblock_reserve_offset;
    int64_t memblock_alloc_try_nid_offset;
    int64_t vabits_flag;
    int64_t memstart_addr_offset;
    int64_t kimage_voffset_offset;
    int64_t memblock_mark_nomap_offset;

    uint8_t header_backup[HDR_BACKUP_SIZE];
    uint8_t superkey[SUPER_KEY_LEN];
} setup_preset_t;
#else
#define setup_kernel_size_offset 0
#define setup_page_shift_offset 8
#define setup_kp_offset_offset 0x10
#define setup_start_offset_offset 0x18
#define setup_map_offset_offset 0x20
#define setup_map_max_size_offset 0x28
#define setup_kallsyms_lookup_name_offset_offset 0x30
#define setup_paging_init_offset_offset 0x38
#define setup_printk_offset_offset 0x40
#define setup_memblock_reserve_offset_offset 0x48
#define setup_memblock_alloc_try_nid_offset_offset 0x50
#define setup_vabits_flag_offset 0x58
#define setup_memstart_addr_offset_offset 0x60
#define setup_kimage_voffset_offset_offset 0x68
#define setup_memblock_mark_nomap_offset 0x70
#define setup_header_backup_offset 0x78
#define setup_superkey_offset (setup_header_backup_offset + HDR_BACKUP_SIZE)
#endif

#ifndef __ASSEMBLY__
typedef struct
{
} setup_config_t;
#endif

#endif // _KP_PRESET_H_