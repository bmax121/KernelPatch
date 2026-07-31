/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_TOOL_X86_64_H_
#define _KP_TOOL_X86_64_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct
{
    char *bzimage;
    size_t bzimage_size;
    size_t payload_start;
    size_t payload_size;

    char *elf;
    size_t elf_size;

    char *flat;
    size_t flat_size;
    uint64_t phys_base;
    uint64_t virt_base;

    char *suffix_payload;
    size_t suffix_payload_size;
} x86_bzimage_t;

bool is_x86_bzimage(const void *data, size_t size);
int load_x86_bzimage(const char *path, x86_bzimage_t *image);
int write_x86_bzimage(x86_bzimage_t *image, const char *path);
int sync_x86_flat_to_elf(x86_bzimage_t *image);
int inject_x86_kpimg(x86_bzimage_t *image, void *kpimg, size_t kpimg_size);
int remove_x86_kpimg(x86_bzimage_t *image);
void free_x86_bzimage(x86_bzimage_t *image);

#endif
