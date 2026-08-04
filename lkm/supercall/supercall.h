/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */
#ifndef _KP_LKM_SUPERCALL_H_
#define _KP_LKM_SUPERCALL_H_
#include <linux/types.h>

/* Hook syscall 45 (truncate) with the supercall handler. Saves the original
 * entry for passthrough. Returns 0 on success. */
int kp_supercall_install(void);

/* Restore syscall 45. */
void kp_supercall_uninstall(void);

#endif /* _KP_LKM_SUPERCALL_H_ */
