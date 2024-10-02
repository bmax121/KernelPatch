/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <predata.h>
#include <common.h>
#include <log.h>
#include <sha256.h>
#include <symbol.h>

#include "start.h"
#include "pgtable.h"
#include "baselib.h"

extern start_preset_t start_preset;

static char *superkey = 0;
static char *root_superkey = 0;

struct patch_config *patch_config = 0;
KP_EXPORT_SYMBOL(patch_config);

static const char bstr[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static uint64_t _rand_next = 1000000007;
static bool enable_root_key = false;

int auth_superkey(const char *key)
{
    int rc = 0;
    for (int i = 0; superkey[i]; i++) {
        rc |= (superkey[i] ^ key[i]);
    }
    if (!rc) goto out;

    if (!enable_root_key) goto out;

    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const BYTE *)key, lib_strnlen(key, SUPER_KEY_LEN));
    sha256_final(&ctx, hash);
    int len = SHA256_BLOCK_SIZE > ROOT_SUPER_KEY_HASH_LEN ? ROOT_SUPER_KEY_HASH_LEN : SHA256_BLOCK_SIZE;
    rc = lib_memcmp(root_superkey, hash, len);

    static bool first_time = true;
    if (!rc && first_time) {
        first_time = false;
        reset_superkey(key);
        enable_root_key = false;
    }

out:
    return !!rc;
}

void reset_superkey(const char *key)
{
    lib_strlcpy(superkey, key, SUPER_KEY_LEN);
    dsb(ish);
}

void enable_auth_root_key(bool enable)
{
    enable_root_key = enable;
}

uint64_t rand_next()
{
    _rand_next = 1103515245 * _rand_next + 12345;
    return _rand_next;
}

const char *get_superkey()
{
    return superkey;
}

int on_each_extra_item(int (*callback)(const patch_extra_item_t *extra, const char *arg, const void *con, void *udata),
                       void *udata)
{
    int rc = 0;
    uint64_t item_addr = _kp_extra_start;
    while (item_addr < _kp_extra_end) {
        patch_extra_item_t *item = (patch_extra_item_t *)item_addr;
        if (item->type == EXTRA_TYPE_NONE) break;
        for (int i = 0; i < sizeof(item->magic); i++) {
            if (item->magic[i] != EXTRA_HDR_MAGIC[i]) break;
        }
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
    root_superkey = (char *)start_preset.root_superkey;
    char *compile_time = start_preset.header.compile_time;

    // RNG
    _rand_next *= kernel_va;
    _rand_next *= kver;
    _rand_next *= kpver;
    _rand_next *= _kp_region_start;
    _rand_next *= _kp_region_end;
    if (*(uint64_t *)compile_time) _rand_next *= *(uint64_t *)compile_time;
    if (*(uint64_t *)(superkey)) _rand_next *= *(uint64_t *)(superkey);
    if (*(uint64_t *)(root_superkey)) _rand_next *= *(uint64_t *)(root_superkey);

    enable_root_key = false;

    // random key
    if (lib_strnlen(superkey, SUPER_KEY_LEN) <= 0) {
        enable_root_key = true;
        int len = SUPER_KEY_LEN > 16 ? 16 : SUPER_KEY_LEN;
        len--;
        for (int i = 0; i < len; ++i) {
            uint64_t rand = rand_next() % (sizeof(bstr) - 1);
            superkey[i] = bstr[rand];
        }
    }
    log_boot("gen rand key: %s\n", superkey);

    patch_config = &start_preset.patch_config;

    for (uintptr_t addr = (uint64_t)patch_config; addr < (uintptr_t)patch_config + PATCH_CONFIG_LEN;
         addr += sizeof(uintptr_t)) {
        uintptr_t *p = (uintptr_t *)addr;
        if (*p) *p += kernel_va;
    }

    dsb(ish);
}