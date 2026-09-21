/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#include <stdint.h>

#include "patch.h"

#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define PAGE_SIZE_DEFAULT 4096

#define LZ4_MAGIC 0x184c2102
#define LZ4_BLOCK_SIZE 0x800000
#define LZ4HC_CLEVEL 12
#define AVB_FOOTER_SIZE 64
#define AVB_FOOTER_MAGIC "AVBf"
#define AVB_FOOTER_VERSION 1
/* An AvbVBMetaImageHeader is 256 bytes, so nothing smaller can be metadata. */
#define AVB_VBMETA_MIN_SIZE 256

struct boot_img_hdr {
    uint8_t magic[8];           // "ANDROID!"
    uint32_t kernel_size;
    uint32_t kernel_addr;     //when it come to V3 ,it should be ramdisk_size
    uint32_t ramdisk_size;
    uint32_t ramdisk_addr;
    uint32_t second_size;
    uint32_t second_addr;
    uint32_t tags_addr;
    uint32_t page_size;         // 4096
    uint32_t unused[2];
    uint8_t name[16];
    uint8_t cmdline[512];
    uint32_t id[8];
	uint8_t extra_cmdline[1024];     // command

    // v2 
    uint32_t recovery_dtbo_size;     
    uint64_t recovery_dtbo_offset;   
         
    
    // v3 
    uint32_t dtb_size;               
    uint64_t dtb_addr;               
};
struct kernel_hdr {
	uint32_t code0;      // Executable code
    uint32_t code1;      // Executable code
    uint64_t text_offset; // Image load offset, little endian
    uint64_t image_size;  // Effective Image size, little endian
    uint64_t flags;       // kernel flags, little endian
    uint64_t res2;        // reserved
    uint64_t res3;        // reserved
    uint64_t res4;        // reserved
    uint32_t magic;       // Magic number, "ARM\x64"
    uint32_t res5;        // reserved
	
};

typedef struct {
     uint8_t magic[8];
} compress_head;

#define DTB_MAGIC "\xd0\x0d\xfe\xed"

struct fdt_header {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};
/*
 * AVB footer: the last AVB_FOOTER_SIZE bytes of the image, starting with
 * "AVBf".  Layout observed on stock boot images (header v3/v4 GKI and Pixel
 * images, and what the manager side locates the metadata with):
 *
 *   0   magic[4]              "AVBf"
 *   4   version[4]            1, big endian
 *   8   reserved0[4]          0 on every image seen so far
 *   12  image_size[8]         original_image_size, big endian
 *   20  vbmeta_offset[8]      big endian
 *   28  vbmeta_size[8]        big endian
 *   36  reserved1[28]
 *
 * The numbers are kept as byte arrays so the footer can be copied around and
 * patched without host endianness or alignment concerns.  The repacker only
 * rewrites image_size and vbmeta_offset (shifted by the padded kernel size
 * change) and copies every other byte from the original footer, so fields it
 * does not know about survive untouched.
 */
struct avb_footer {
    uint8_t magic[4];              /* "AVBf" */
    uint8_t version[4];            /* big endian, 1 */
    uint8_t reserved0[4];
    uint8_t image_size[8];         /* original_image_size */
    uint8_t vbmeta_offset[8];      /* offset of the vbmeta blob */
    uint8_t vbmeta_size[8];        /* size of the vbmeta blob */
    uint8_t reserved1[28];
} __attribute__((packed));

int repack_bootimg(const char *orig_boot_path,
                        const char *new_kernel_path,
                        const char *out_boot_path);
int repack_bootimg_mem(const char *orig_boot_path,
                       const uint8_t *new_kernel, uint32_t new_kernel_size,
                       const char *out_boot_path);
int extract_kernel(const char *bootimg_path);

int is_bootimg(const char *path);
int patch_bootimg(const char *bootimg_path, const char *kpimg_path, const char *out_boot_path,
                  const char *superkey, bool root_key, const char **additional,
                  extra_config_t *extra_configs, int extra_config_num);

int detect_compress_method(compress_head data);
int compress_raw_deflate(const uint8_t *in_data, int in_len, uint8_t **out_data, int *out_len);
int cacluate_sha1(const char *file);
void *memmem(const void *haystack, size_t haystacklen,const void *needle, size_t needlelen);