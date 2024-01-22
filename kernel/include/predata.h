/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_PREDATA_H_
#define _KP_PREDATA_H_

#include <ktypes.h>
#include <stdbool.h>
#include <preset.h>

int superkey_auth(const char *key, int len);
const char *get_superkey();
struct patch_symbol *get_preset_patch_sym();

void predata_init();

#endif