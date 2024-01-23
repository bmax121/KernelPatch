/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "common.h"

void read_img(const char *path, char **con, int *len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) tools_error_exit("open file: %s, %s\n", path, strerror(errno));
    fseek(fp, 0, SEEK_END);
    long img_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = (char *)malloc(img_len);
    int readlen = fread(buf, 1, img_len, fp);
    if (readlen != img_len) tools_error_exit("read file: %s incomplete\n", path);
    fclose(fp);
    *con = buf;
    *len = img_len;
}

void write_img(const char *path, char *img, int len)
{
    FILE *fout = fopen(path, "wb");
    if (!fout) tools_error_exit("open %s %s\n", path, strerror(errno));
    int writelen = fwrite(img, 1, len, fout);
    if (writelen != len) tools_error_exit("write file: %s incomplete\n", path);
    fclose(fout);
}
