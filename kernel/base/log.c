/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <stdint.h>

#define BOOT_LOG_SIZE 1024

static char boot_log[BOOT_LOG_SIZE] = { 0 };
static int boot_log_len = 0;
static int boot_log_fin = 0;
