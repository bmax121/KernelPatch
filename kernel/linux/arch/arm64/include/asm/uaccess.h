/*
 * Based on arch/arm/include/asm/uaccess.h
 *
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_UACCESS_H
#define __ASM_UACCESS_H

#include <linux/thread_info.h>

// todo:

#define VERIFY_READ 0
#define VERIFY_WRITE 1

#define KERNEL_DS (-1UL)
// #define get_ds() (KERNEL_DS)

// #define USER_DS TASK_SIZE_64
// #define get_fs() (current_thread_info()->addr_limit)

// static inline void set_fs(mm_segment_t fs)
// {
//     current_thread_info()->addr_limit = fs;
// }

// #define segment_eq(a, b) ((a) == (b))

#endif