/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */
#ifndef _KP_LKM_DISPATCH_H_
#define _KP_LKM_DISPATCH_H_
#include <linux/types.h>

/* Dispatch one supercall command. @a1..@a4 are the raw syscall args beyond
 * cmd (matching the kernel/patch/common/supercall.c switch). */
long kp_handle_supercall(long cmd, long a1, long a2, long a3, long a4);

#endif /* _KP_LKM_DISPATCH_H_ */
