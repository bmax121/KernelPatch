/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_PREDATA_H_
#define _KP_PREDATA_H_

#include <ktypes.h>
#include <stdbool.h>
#include <preset.h>

int superkey_auth(const char *key);
const char *get_superkey();
struct patch_symbol *get_preset_patch_sym();
int on_each_extra_item(int (*callback)(const patch_extra_item_t *extra, const char *arg, const void *data, void *udata),
                       void *udata);

void predata_init();

#endif