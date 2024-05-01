/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_PRESET_H_
#define _KP_PRESET_H_

#ifndef __ASSEMBLY__
#include <stdint.h>
#endif

#define KP_MAGIC "KP1158"
#define MAGIC_LEN 0x8
#define KP_HEADER_SIZE 0x40
#define SUPER_KEY_LEN 0x40
#define ROOT_SUPER_KEY_HASH_LEN 0x20
#define SETUP_PRESERVE_LEN 0x40
#define HDR_BACKUP_SIZE 0x8
#define COMPILE_TIME_LEN 0x18
#define MAP_MAX_SIZE 0xa00
#define HOOK_ALLOC_SIZE (1 << 20)
#define MEMORY_ROX_SIZE (2 << 20)
#define MEMORY_RW_SIZE (2 << 20)
#define MAP_ALIGN 0x10

#define CONFIG_DEBUG (1 << 0)
#define CONFIG_ANDROID (1 << 1)

#define MAP_SYMBOL_NUM (5)
#define MAP_SYMBOL_SIZE (MAP_SYMBOL_NUM * 8)

#define PATCH_SYMBOL_LEN (512)

#define ADDITIONAL_LEN (512)

#define PATCH_EXTRA_ITEM_LEN (128)

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

typedef uint64_t config_t;

typedef struct _setup_header_t // 64-bytes
{
    union
    {
        struct
        {
            char magic[MAGIC_LEN]; //
            version_t kp_version;
            uint32_t _;
            config_t config_flags;
            char compile_time[COMPILE_TIME_LEN];
        };
        char _cap[64];
    };
} setup_header_t;

_Static_assert(sizeof(setup_header_t) == KP_HEADER_SIZE, "sizeof setup_header_t mismatch");

#else
#define header_magic_offset 0
#define header_kp_version_offset (MAGIC_LEN)
#define header_config_flags (header_kp_version_offset + 4 + 4)
#define header_compile_time_offset (header_config_flags + 8)
#endif

#ifndef __ASSEMBLY__
struct map_symbol
{
    union
    {
        struct
        {
            uint64_t memblock_reserve_relo;
            uint64_t memblock_free_relo;
            uint64_t memblock_phys_alloc_relo;
            uint64_t memblock_virt_alloc_relo;
            uint64_t memblock_mark_nomap_relo;
        };
        char _cap[MAP_SYMBOL_SIZE];
    };
};
typedef struct map_symbol map_symbol_t;
_Static_assert(sizeof(map_symbol_t) == MAP_SYMBOL_SIZE, "sizeof map_symbol_t mismatch");
#endif

#ifndef __ASSEMBLY__
struct patch_symbol
{
    union
    {
        struct
        {
            uint64_t kallsyms_lookup_name;
            uint64_t printk;
            uint64_t vm_area_add_early;

            uint64_t panic;
            uint64_t rest_init;
            uint64_t cgroup_init;
            uint64_t kernel_init;
            uint64_t report_cfi_failure;
            uint64_t __cfi_slowpath_diag;
            uint64_t __cfi_slowpath;
            uint64_t copy_process;
            uint64_t cgroup_post_fork;
            uint64_t do_execveat_common;
            uint64_t __do_execve_file;
            uint64_t do_execve_common;
            uint64_t do_faccessat;
            uint64_t sys_faccessat;
            uint64_t sys_faccessat2;
            uint64_t sys_newfstatat;
            uint64_t vfs_statx;
            uint64_t vfs_fstatat;
            uint64_t avc_denied;
            uint64_t slow_avc_audit;
            uint64_t input_handle_event;
        };
        char _cap[PATCH_SYMBOL_LEN];
    };
};
typedef struct patch_symbol patch_symbol_t;
_Static_assert(sizeof(patch_symbol_t) == PATCH_SYMBOL_LEN, "sizeof patch_symbol_t mismatch");
#endif

#ifndef __ASSEMBLY__

#define EXTRA_ALIGN 0x10
#define EXTRA_NAME_LEN 0x20
#define EXTRA_EVENT_LEN 0x20

#define EXTRA_HDR_MAGIC "kpe"

typedef int32_t extra_item_type;

#define EXTRA_TYPE_NONE 0
#define EXTRA_TYPE_KPM 1
#define EXTRA_TYPE_SHELL 2
#define EXTRA_TYPE_EXEC 3
#define EXTRA_TYPE_RAW 4
#define EXTRA_TYPE_ANDROID_RC 5

#define EXTRA_TYPE_NONE_STR "none"
#define EXTRA_TYPE_KPM_STR "kpm"
#define EXTRA_TYPE_SHELL_STR "shell"
#define EXTRA_TYPE_EXEC_STR "exec"
#define EXTRA_TYPE_RAW_STR "raw"
#define EXTRA_TYPE_ANDROID_RC_STR "android_rc"

// todo
#define EXTRA_EVENT_PAGING_INIT "paging-init"

#define EXTRA_EVENT_PRE_KERNEL_INIT "pre-kernel-init"
#define EXTRA_EVENT_KPM_DEFAULT EXTRA_EVENT_PRE_KERNEL_INIT
#define EXTRA_EVENT_POST_KERNEL_INIT "post-kernel-init"

#define EXTRA_EVENT_PRE_FIRST_STAGE "pre-init-first-stage"
#define EXTRA_EVENT_POST_FIRST_STAGE "post-init-first-stage"

#define EXTRA_EVENT_PRE_EXEC_INIT "pre-exec-init"
#define EXTRA_EVENT_POST_EXEC_INIT "post-exec-init"

#define EXTRA_EVENT_PRE_SECOND_STAGE "pre-init-second-stage"
#define EXTRA_EVENT_POST_SECOND_STAGE "post-init-second-stage"

struct _patch_extra_item
{
    union
    {
        struct
        {
            char magic[4];
            int32_t priority;
            int32_t args_size;
            int32_t con_size;
            extra_item_type type;
            char name[EXTRA_NAME_LEN];
            char event[EXTRA_EVENT_LEN];
        };
        char _cap[PATCH_EXTRA_ITEM_LEN];
    };
};
typedef struct _patch_extra_item patch_extra_item_t;
_Static_assert(sizeof(patch_extra_item_t) == PATCH_EXTRA_ITEM_LEN, "sizeof patch_extra_item_t mismatch");
#endif

#ifndef __ASSEMBLY__

// TODO: remove
typedef struct
{
    version_t kernel_version;
    int32_t _;
    int64_t kimg_size; // must aligned
    int64_t kpimg_size; // must aligned
    int64_t kernel_size; // must aligned
    int64_t page_shift;
    int64_t setup_offset; // must aligned
    int64_t start_offset; // must aligned
    int64_t extra_size; // must aligned
    int64_t map_offset; // must aligned MAP_ALIGN
    int64_t map_max_size;
    int64_t kallsyms_lookup_name_offset;
    int64_t paging_init_offset;
    int64_t printk_offset;
    map_symbol_t map_symbol;
    uint8_t header_backup[HDR_BACKUP_SIZE];
    uint8_t superkey[SUPER_KEY_LEN];
    patch_symbol_t patch_symbol;
    char additional[ADDITIONAL_LEN];
} setup_preset_be_000a04_t;

typedef struct _setup_preset_t
{
    version_t kernel_version;
    int32_t _;
    int64_t kimg_size; // must aligned
    int64_t kpimg_size; // must aligned
    int64_t kernel_size; // must aligned
    int64_t page_shift;
    int64_t setup_offset; // must aligned
    int64_t start_offset; // must aligned
    int64_t extra_size; // must aligned
    int64_t map_offset; // must aligned MAP_ALIGN
    int64_t map_max_size;
    int64_t kallsyms_lookup_name_offset;
    int64_t paging_init_offset;
    int64_t printk_offset;
    map_symbol_t map_symbol;
    uint8_t header_backup[HDR_BACKUP_SIZE];
    uint8_t superkey[SUPER_KEY_LEN];
    uint8_t root_superkey[ROOT_SUPER_KEY_HASH_LEN];
    uint8_t __[SETUP_PRESERVE_LEN];
    patch_symbol_t patch_symbol;
    char additional[ADDITIONAL_LEN];
} setup_preset_t;
#else
#define setup_kernel_version_offset 0
#define setup_kimg_size_offset (setup_kernel_version_offset + 8)
#define setup_kpimg_size_offset (setup_kimg_size_offset + 8)
#define setup_kernel_size_offset (setup_kpimg_size_offset + 8)
#define setup_page_shift_offset (setup_kernel_size_offset + 8)
#define setup_setup_offset_offset (setup_page_shift_offset + 8)
#define setup_start_offset_offset (setup_setup_offset_offset + 8)
#define setup_extra_size_offset (setup_start_offset_offset + 8)
#define setup_map_offset_offset (setup_extra_size_offset + 8)
#define setup_map_max_size_offset (setup_map_offset_offset + 8)
#define setup_kallsyms_lookup_name_offset_offset (setup_map_max_size_offset + 8)
#define setup_paging_init_offset_offset (setup_kallsyms_lookup_name_offset_offset + 8)
#define setup_printk_offset_offset (setup_paging_init_offset_offset + 8)
#define setup_map_symbol_offset (setup_printk_offset_offset + 8)
#define setup_header_backup_offset (setup_map_symbol_offset + MAP_SYMBOL_SIZE)
#define setup_superkey_offset (setup_header_backup_offset + HDR_BACKUP_SIZE)
#define setup_root_superkey_offset (setup_superkey_offset + SUPER_KEY_LEN)
#define setup_patch_symbol_offset (setup_root_superkey_offset + ROOT_SUPER_KEY_HASH_LEN + SETUP_PRESERVE_LEN)
#define setup_end (setup_patch_symbol_offset + PATCH_SYMBOL_LEN)
#endif

#ifndef __ASSEMBLY__
typedef struct
{
    setup_header_t header;
    setup_preset_t setup;
} preset_t;
#endif

#endif // _KP_PRESET_H_