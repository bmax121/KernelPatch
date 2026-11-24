/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_HOOK_RUNTIME_H_
#define _KP_LKM_HOOK_RUNTIME_H_

#include <linux/types.h>

int kp_hook_runtime_init(void);
bool kp_hook_cfi_allowed_addr(unsigned long addr);

#endif