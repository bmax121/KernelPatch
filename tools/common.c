/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "common.h"

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

void read_img_align(const char *path, char **con, int *len, int align)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) tools_error_exit("open file: %s, %s\n", path, strerror(errno));
    fseek(fp, 0, SEEK_END);
    long img_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    long align_img_len = align_ceil(img_len, align);
    char *buf = (char *)malloc(align_img_len);
    memset(buf + img_len, 0, align_img_len - img_len);
    int readlen = fread(buf, 1, img_len, fp);
    if (readlen != img_len) tools_error_exit("read file: %s incomplete\n", path);
    fclose(fp);
    *con = buf;
    *len = align_img_len;
}

void write_img(const char *path, char *img, int len)
{
    FILE *fout = fopen(path, "wb");
    if (!fout) tools_error_exit("open %s %s\n", path, strerror(errno));
    int writelen = fwrite(img, 1, len, fout);
    if (writelen != len) tools_error_exit("write file: %s incomplete\n", path);
    fclose(fout);
}
