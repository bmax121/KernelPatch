/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <predata.h>
#include <common.h>
#include <log.h>

#include "start.h"
#include "pgtable.h"
#include "baselib.h"

extern start_preset_t start_preset;

static char *superkey = 0;
static struct patch_symbol *patch_symbol = 0;

int superkey_auth(const char *key)
{
    return lib_strncmp(superkey, key, SUPER_KEY_LEN);
}

const char *get_superkey()
{
    return superkey;
}

struct patch_symbol *get_preset_patch_sym()
{
    return patch_symbol;
}

int on_each_extra_item(int (*callback)(const patch_extra_item_t *extra, const char *arg, const void *con, void *udata),
                       void *udata)
{
    int rc = 0;
    uint64_t item_addr = _kp_extra_start;
    while (item_addr < _kp_extra_end) {
        patch_extra_item_t *item = (patch_extra_item_t *)item_addr;
        if (item->type == EXTRA_TYPE_NONE) break;
        const char *args = item->args_size > 0 ? (const char *)(item_addr + sizeof(patch_extra_item_t)) : 0;
        const void *con = (void *)(item_addr + sizeof(patch_extra_item_t) + item->args_size);
        rc = callback(item, args, con, udata);
        if (rc) break;
        item_addr += sizeof(patch_extra_item_t);
        item_addr += item->args_size;
        item_addr += item->con_size;
    }
    return rc;
}

void predata_init()
{
    superkey = (char *)start_preset.superkey;

    patch_symbol = &start_preset.patch_symbol;

    for (uintptr_t addr = (uint64_t)patch_symbol; addr < (uintptr_t)patch_symbol + PATCH_SYMBOL_LEN;
         addr += sizeof(uintptr_t)) {
        uintptr_t *p = (uintptr_t *)addr;
        if (*p) *p += kernel_va;
    }
}