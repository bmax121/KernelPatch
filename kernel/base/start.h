#ifndef _KP_START_H_
#define _KP_START_H_

#include <ktypes.h>
#include "setup.h"

#define bits(n, high, low) (((n) << (63u - (high))) >> (63u - (high) + (low)))
#define align_floor(x, align) ((uint64_t)(x) & ~((uint64_t)(align)-1))
#define align_ceil(x, align) (((uint64_t)(x) + (uint64_t)(align)-1) & ~((uint64_t)(align)-1))

typedef struct
{
    version_t kernel_version;
    version_t kp_version;
    char compile_time[32];
    int32_t kallsyms_lookup_name_offset;
    int32_t kernel_size;
    int32_t map_offset;
    int32_t map_backup_len;
    uint8_t superkey[SUPER_KEY_LEN];
    uint8_t map_backup[MAP_MAX_SIZE];
} start_preset_t;

extern start_preset_t start_preset;

int start(uint64_t kpa, uint64_t kva);
int predata_init();

void _kp_start();
void _kp_text_start();
void _kp_text_end();
void _kp_data_start();
void _kp_data_end();
void _kp_end();

#endif