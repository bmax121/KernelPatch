/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_PREDATA_H_
#define _KP_PREDATA_H_

#include <ktypes.h>
#include <preset.h>

extern struct patch_config *patch_config;
extern setup_header_t *setup_header;

int auth_superkey(const char *key);
void reset_superkey(const char *key);
void enable_auth_root_key(bool enable);
const char *get_superkey();
const char *get_build_time();
uint64_t rand_next();

int on_each_extra_item(int (*callback)(const patch_extra_item_t *extra, const char *arg, const void *data, void *udata),
                       void *udata);

void predata_init();

#endif