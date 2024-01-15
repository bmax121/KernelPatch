/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "patch.h"

preset_t *get_preset(const char *kimg, int kimg_len)
{
    char magic[MAGIC_LEN] = "KP1158";
    return (preset_t *)memmem(kimg, kimg_len, magic, sizeof(magic));
}

static int read_img(const char *path, char **con, int *len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return errno;
    fseek(fp, 0, SEEK_END);
    long img_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = (char *)malloc(img_len);
    fread(buf, 1, img_len, fp);
    fclose(fp);
    *con = buf;
    *len = img_len;
    return 0;
}

int patch(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey)
{
    if (!kimg_path || !kpimg_path || !out_path || !superkey) {
        return -EINVAL;
    }
    int rc = 0;
    char *kimg = NULL, kpimg = NULL;
    int kimg_len = 0, kpimg_len = 0;
    if (read_img(kimg_path, &kimg, &kpimg_len)) {
    }
}

int unpatch(const char *kimg_path, const char *out_path);