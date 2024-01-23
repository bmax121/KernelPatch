/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define tools_error_exit(fmt, ...)                                                                  \
    do {                                                                                            \
        fprintf(stdout, "[-] error %s:%d/%s(); " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
        exit(EXIT_FAILURE);                                                                         \
    } while (0)

#define tools_loge(fmt, ...) fprintf(stdout, "[-] error %s:%d/%s(); " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__);

#define tools_logi(fmt, ...) fprintf(stdout, "[+] %s; " fmt, __FILE__, ##__VA_ARGS__);

#define tools_logw(fmt, ...) fprintf(stdout, "[?] %s; " fmt, __FILE__, ##__VA_ARGS__);

void read_img(const char *path, char **con, int *len);
void write_img(const char *path, char *img, int len);