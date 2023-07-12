#ifndef _KP_START_H_
#define _KP_START_H_

#include "setup.h"

#define bits(n, high, low) (((n) << (63u - (high))) >> (63u - (high) + (low)))
#define align_floor(x, align) ((uint64_t)(x) & ~((uint64_t)(align)-1))
#define align_ceil(x, align) (((uint64_t)(x) + (uint64_t)(align)-1) & ~((uint64_t)(align)-1))

#ifndef __ASSEMBLY__
typedef struct
{
    version_t kernel_version;
    version_t kp_version;
    int64_t kallsyms_lookup_name_offset;
    int64_t kernel_size;
    int64_t start_offset;
    uint64_t kernel_pa;
    int64_t map_offset;
    int64_t map_backup_len;
    char compile_time[COMPILE_TIME_LEN];
    uint8_t superkey[SUPER_KEY_LEN];
    uint8_t map_backup[MAP_MAX_SIZE];
} start_preset_t;
#else
#define start_kernel_version_offset 0
#define start_kp_version_offset 0x4
#define start_kallsyms_lookup_name_offset_offset 0x8
#define start_kernel_size_offset 0x10
#define start_start_offset_offset 0x18
#define start_kernel_pa_offset 0x20
#define start_map_offset_offset 0x28
#define start_map_backup_len_offset 0x30
#define start_compile_time_offset 0x38
#define start_superkey_offset (start_compile_time_offset + COMPILE_TIME_LEN)
#define start_map_backup_offset (start_superkey_offset + SUPER_KEY_LEN)
#endif

#ifndef __ASSEMBLY__

extern start_preset_t start_preset;

int predata_init();

void _kp_start();
void _kp_text_start();
void _kp_text_end();
void _kp_data_start();
void _kp_data_end();
void _kp_end();

#endif

#endif // _KP_START_H_