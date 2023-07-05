#ifndef _PRESET_H_
#define _PRESET_H_

#include <stdint.h>

#define KP_HEADER_SIZE 64
#define SUPER_KEY_LEN 32
#define HDR_BACKUP_SIZE 8

#define VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))

typedef struct __attribute__((packed)) version_t
{
    uint8_t _;
    uint8_t patch;
    uint8_t minor;
    uint8_t major;
} version_t;

typedef struct __attribute__((packed)) _setup_header_t
{
    char magic[8];
    version_t kp_version;
    char compile_time[24];
    char _reserved[12];
} setup_header_t;

typedef struct __attribute__((packed)) _setup_preset_t
{
    version_t kernel_version;

    int32_t kernel_size;
    int32_t page_shift;

    int32_t kp_offset;
    int32_t map_offset; // must be divisibled by MAP_ALIGN
    int32_t map_max_size;

    int32_t _ksym_offset_start[0];
    int32_t kallsyms_lookup_name_offset;
    int32_t start_kernel_offset;
    int32_t paging_init_offset;
    int32_t printk_offset;
    int32_t memblock_reserve_offset;
    int32_t memblock_alloc_try_nid_offset;
    int32_t vabits_actual_offset;
    int32_t memstart_addr_offset;
    int32_t kimage_voffset_offset;
    int32_t _ksym_offset_end[0];

    uint8_t header_backup[HDR_BACKUP_SIZE];
    uint8_t superkey[SUPER_KEY_LEN];
} setup_preset_t;

typedef struct
{
} setup_config_t;

#endif
