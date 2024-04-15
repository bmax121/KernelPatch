/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_PATCHING_H_
#define _KP_PATCHING_H_

#include <stdint.h>

int kp_insn_patch_text(void *addrs[], uint32_t insn[], int cnt);

#endif