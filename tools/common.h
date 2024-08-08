/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_COMMON_H_
#define _KP_TOOL_COMMON_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#include <string.h>

extern bool log_enable;

#define tools_logi(fmt, ...) \
    if (log_enable) fprintf(stdout, "[+] " fmt, ##__VA_ARGS__);

#define tools_logw(fmt, ...) \
    if (log_enable) fprintf(stdout, "[?] " fmt, ##__VA_ARGS__);

#define tools_loge(fmt, ...) \
    if (log_enable) fprintf(stdout, "[-] %s:%d/%s(); " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__);

#define tools_loge_exit(fmt, ...)                                                             \
    do {                                                                                      \
        fprintf(stderr, "[-] %s:%d/%s(); " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
        exit(EXIT_FAILURE);                                                                   \
    } while (0)

#define tools_log_errno_exit(fmt, ...)                                                                 \
    do {                                                                                               \
        fprintf(stderr, "[-] %s:%d/%s(); " fmt " - %s\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__, \
                strerror(errno));                                                                      \
        exit(errno);                                                                                   \
    } while (0)

#define SZ_4K 0x1000

#define align_floor(x, align) ((uint64_t)(x) & ~((uint64_t)(align)-1))
#define align_ceil(x, align) (((uint64_t)(x) + (uint64_t)(align)-1) & ~((uint64_t)(align)-1))

#define INSN_IS_B(inst) (((inst) & 0xFC000000) == 0x14000000)

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))

#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)

static inline void set_log_enable(bool enable)
{
    log_enable = enable;
}

int can_b_imm(uint64_t from, uint64_t to);
int b(uint32_t *buf, uint64_t from, uint64_t to);
int32_t relo_branch_func(const char *img, int32_t func_offset);

void write_file(const char *path, const char *con, int len, bool append);

void read_file_align(const char *path, char **con, int *len, int align);

int64_t int_unpack(void *ptr, int32_t size, bool is_be);
uint64_t uint_unpack(void *ptr, int32_t size, bool is_be);

static inline void read_file(const char *path, char **con, int *len)
{
    return read_file_align(path, con, len, 1);
}

#endif
