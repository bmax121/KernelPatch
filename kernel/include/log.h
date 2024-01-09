/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_LOG_H_
#define _KP_LOG_H_

#include <stdint.h>

#define PREFIX_MAX 48
#define LOG_LINE_MAX (1024 - PREFIX_MAX)

extern void (*printk)(const char *fmt, ...);

#define logkv(fmt, ...) printk("[+] KP V " fmt, ##__VA_ARGS__)
// #define logkv(fmt, ...)

// #define logkfv(fmt, ...) printk("[+] KP V %s: " fmt, __func__, ##__VA_ARGS__)
#define logkfv(fmt, ...)

#define logkd(fmt, ...) printk("[+] KP D " fmt, ##__VA_ARGS__)
#define logkfd(fmt, ...) printk("[+] KP D %s: " fmt, __func__, ##__VA_ARGS__)

#define logki(fmt, ...) printk("[+] KP I " fmt, ##__VA_ARGS__)
#define logkfi(fmt, ...) printk("[+] KP I %s: " fmt, __func__, ##__VA_ARGS__)

#define logkw(fmt, ...) printk("[-] KP W " fmt, ##__VA_ARGS__)
#define logkfw(fmt, ...) printk("[-] KP W %s: " fmt, __func__, ##__VA_ARGS__)

#define logke(fmt, ...) printk("[-] KP E " fmt, ##__VA_ARGS__)
#define logkfe(fmt, ...) printk("[-] KP E %s: " fmt, __func__, ##__VA_ARGS__)

void log_boot(const char *fmt, ...);
const char *get_boot_log();

#endif