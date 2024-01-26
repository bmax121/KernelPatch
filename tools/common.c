/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "common.h"
#include "order.h"

bool log_enable = false;

int can_b_imm(uint64_t from, uint64_t to)
{
    // B: 128M
    uint32_t imm26 = 1 << 25 << 2;
    return (to >= from && to - from <= imm26) || (from >= to && from - to <= imm26);
}

int b(uint32_t *buf, uint64_t from, uint64_t to)
{
    if (can_b_imm(from, to)) {
        buf[0] = 0x14000000u | (((to - from) & 0x0FFFFFFFu) >> 2u);
        return 4;
    }
    return 0;
}

int32_t relo_branch_func(const char *img, int32_t func_offset)
{
    uint32_t inst = *(uint32_t *)(img + func_offset);
    int32_t relo_offset = func_offset;
    if (INSN_IS_B(inst)) {
        uint64_t imm26 = bits32(inst, 25, 0);
        uint64_t imm64 = sign64_extend(imm26 << 2u, 28u);
        relo_offset = func_offset + (int32_t)imm64;
        tools_logi("relocate branch function 0x%x to 0x%x\n", func_offset, relo_offset);
    }
    return relo_offset;
}

void read_file_align(const char *path, char **con, int *out_len, int align)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) tools_error_exit("open file: %s, %s\n", path, strerror(errno));
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    long align_len = align_ceil(len, align);
    char *buf = (char *)malloc(align_len);
    memset(buf + len, 0, align_len - len);
    int readlen = fread(buf, 1, len, fp);
    if (readlen != len) tools_error_exit("read file: %s incomplete\n", path);
    fclose(fp);
    *con = buf;
    *out_len = align_len;
}

void write_file(const char *path, const char *con, int len, bool append)
{
    FILE *fout = fopen(path, append ? "a" : "w");
    if (!fout) tools_error_exit("open %s %s\n", path, strerror(errno));
    int writelen = fwrite(con, 1, len, fout);
    if (writelen != len) tools_error_exit("write file: %s incomplete\n", path);
    fclose(fout);
}

int64_t int_unpack(void *ptr, int32_t size, int32_t is_be)
{
    int16_t res16;
    int32_t res32;
    int64_t res64;
    switch (size) {
    case 8:
        res64 = *(int64_t *)ptr;
        return is_be ? i64be(res64) : i64le(res64);
    case 4:
        res32 = *(int32_t *)ptr;
        return is_be ? i32be(res32) : i32le(res32);
    case 2:
        res16 = *(int16_t *)ptr;
        return is_be ? i16be(res16) : i16le(res16);
    default:
        return *(int8_t *)ptr;
    }
}

uint64_t uint_unpack(void *ptr, int32_t size, int32_t is_be)
{
    uint16_t res16;
    uint32_t res32;
    uint64_t res64;
    switch (size) {
    case 8:
        res64 = *(uint64_t *)ptr;
        return is_be ? u64be(res64) : u64le(res64);
    case 4:
        res32 = *(uint32_t *)ptr;
        return is_be ? u32be(res32) : u32le(res32);
    case 2:
        res16 = *(uint16_t *)ptr;
        return is_be ? u16be(res16) : u16le(res16);
    default:
        return *(uint8_t *)ptr;
    }
}
