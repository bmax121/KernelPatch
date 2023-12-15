#ifndef _KP_START_H_
#define _KP_START_H_

#include <preset.h>

#ifndef __ASSEMBLY__
typedef struct
{
    setup_header_t header;
    version_t kernel_version;
    uint32_t _;
    int64_t kallsyms_lookup_name_offset;
    int64_t kernel_size;
    int64_t start_offset;
    uint64_t kernel_pa;
    int64_t map_offset;
    int64_t map_backup_len;
    uint8_t map_backup[MAP_MAX_SIZE];
    uint8_t superkey[SUPER_KEY_LEN];
    patch_config_t patch_config;
} start_preset_t;
#else
#define start_header_offset 0
#define start_kernel_version_offset (start_header_offset + KP_HEADER_SIZE)
#define start_kallsyms_lookup_name_offset_offset (start_kernel_version_offset + 8)
#define start_kernel_size_offset (start_kallsyms_lookup_name_offset_offset + 8)
#define start_start_offset_offset (start_kernel_size_offset + 8)
#define start_kernel_pa_offset (start_start_offset_offset + 8)
#define start_map_offset_offset (start_kernel_pa_offset + 8)
#define start_map_backup_len_offset (start_map_offset_offset + 8)
#define start_map_backup_offset (start_map_backup_len_offset + 8)
#define start_superkey_offset (start_map_backup_offset + MAP_MAX_SIZE)
#define start_patch_config_offset (start_superkey_offset + SUPER_KEY_LEN)
#endif

#endif // _KP_START_H_