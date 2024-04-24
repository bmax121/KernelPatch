/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_UTILS_H_
#define _KP_UTILS_H_

#include <compiler.h>
#include <ktypes.h>

int __must_check compat_copy_to_user(void __user *to, const void *from, int n);
long compat_strncpy_from_user(char *dest, const char __user *src, long count);
void *__user copy_to_user_stack(const void *data, int len);
uid_t current_uid();
uint64_t get_random_u64(void);

void print_bootlog();

#endif