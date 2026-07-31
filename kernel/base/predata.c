/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <predata.h>
#include <common.h>
#include <log.h>
#include <sha256.h>
#include <symbol.h>
#include <kconfig.h>
#include <kpmalloc.h>

#include "start.h"
#include "pgtable.h"
#include "baselib.h"
#include "puff/puff.h"

extern start_preset_t start_preset;

static char *superkey = 0;
static char *root_superkey = 0;

struct patch_config *patch_config = 0;
KP_EXPORT_SYMBOL(patch_config);

static const char *kernel_config = 0;
static int kernel_config_size = 0;
static char kconfig_value_buf[128];
static const char kconfig_no_value[] = "n";
static int kconfig_scan_done = 0;

static void ensure_kconfig_loaded(void);

static const char bstr[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static uint64_t _rand_next = 1000000007;
static bool enable_root_key = false;
static bool superkey_is_user_set = false;
static bool root_superkey_is_set = false;

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
#ifdef CONFIG_X86_64
    barrier();
#else
    dsb(ish);
#endif
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

const char *get_build_time()
{
    return setup_header->compile_time;
}

static const char *skip_config_prefix(const char *name)
{
    return !lib_strncmp(name, "CONFIG_", 7) ? name + 7 : name;
}

static int config_name_eq(const char *line, const char *name, int name_len)
{
    return !lib_strncmp(line, "CONFIG_", 7) && !lib_strncmp(line + 7, name, name_len) && line[7 + name_len] == '=';
}

static const char *find_config_line(const char *name)
{
    const char *cfg = kernel_config;
    const char *end = kernel_config + kernel_config_size;
    int name_len;

    if (!cfg || !name) return 0;

    name = skip_config_prefix(name);
    name_len = lib_strlen(name);
    if (!name_len) return 0;

    while (cfg < end && *cfg) {
        const char *line = cfg;
        const char *next = lib_memchr(line, '\n', end - line);
        if (!next) next = end;

        if (line + 7 + name_len < next && config_name_eq(line, name, name_len)) return line + 7 + name_len + 1;

        cfg = next + 1;
    }

    return 0;
}

static int config_not_set_eq(const char *line, const char *next, const char *name, int name_len)
{
    const char prefix[] = "# CONFIG_";
    const char suffix[] = " is not set";
    int prefix_len = sizeof(prefix) - 1;
    int suffix_len = sizeof(suffix) - 1;

    return next - line == prefix_len + name_len + suffix_len &&
           !lib_strncmp(line, prefix, prefix_len) &&
           !lib_strncmp(line + prefix_len, name, name_len) &&
           !lib_strncmp(line + prefix_len + name_len, suffix, suffix_len);
}

static int config_is_not_set(const char *name)
{
    const char *cfg = kernel_config;
    const char *end = kernel_config + kernel_config_size;
    int name_len;

    if (!cfg || !name) return 0;

    name = skip_config_prefix(name);
    name_len = lib_strlen(name);
    if (!name_len) return 0;

    while (cfg < end && *cfg) {
        const char *line = cfg;
        const char *next = lib_memchr(line, '\n', end - line);
        if (!next) next = end;

        if (config_not_set_eq(line, next, name, name_len)) return 1;

        cfg = next + 1;
    }

    return 0;
}

int kp_kconfig_available(void)
{
    ensure_kconfig_loaded();
    return kernel_config && kernel_config_size > 0;
}
KP_EXPORT_SYMBOL(kp_kconfig_available);

int kp_kconfig_enabled(const char *name)
{
    ensure_kconfig_loaded();
    const char *value = find_config_line(name);

    return value && (*value == 'y' || *value == 'm');
}
KP_EXPORT_SYMBOL(kp_kconfig_enabled);

const char *kp_kconfig_value(const char *name)
{
    ensure_kconfig_loaded();
    const char *value = find_config_line(name);
    int i = 0;

    if (!value) return config_is_not_set(name) ? kconfig_no_value : 0;

    while (i < (int)sizeof(kconfig_value_buf) - 1 && value[i] && value[i] != '\n' && value[i] != '\r') {
        kconfig_value_buf[i] = value[i];
        i++;
    }
    kconfig_value_buf[i] = 0;
    return kconfig_value_buf;
}
KP_EXPORT_SYMBOL(kp_kconfig_value);

const char *kp_kconfig_data(void)
{
    ensure_kconfig_loaded();
    return kernel_config;
}
KP_EXPORT_SYMBOL(kp_kconfig_data);

int kp_kconfig_size(void)
{
    ensure_kconfig_loaded();
    return kernel_config_size;
}
KP_EXPORT_SYMBOL(kp_kconfig_size);

static int find_ikconfig_deflate(const uint8_t *gz, int64_t gz_len, const uint8_t **deflate_start,
                                 unsigned long *deflate_len, unsigned long *out_len)
{
    if (gz_len < 18) return -1; // 10 header + 2 deflate + 8 trailer minimum
    if (gz[0] != 0x1f || gz[1] != 0x8b || gz[2] != 0x08) return -2; // gzip magic + deflate method

    uint8_t flg = gz[3];
    const uint8_t *pos = gz + 10; // skip ID1,ID2,CM,FLG,MTIME[4],XFL,OS

    if (flg & 0x04) { // FEXTRA
        if (pos + 2 > gz + gz_len) return -3;
        uint32_t xlen = (uint32_t)pos[0] | ((uint32_t)pos[1] << 8);
        pos += 2 + xlen;
    }
    if (flg & 0x08) { // FNAME, NUL-terminated
        while (pos < gz + gz_len && *pos) pos++;
        if (pos >= gz + gz_len) return -4;
        pos++;
    }
    if (flg & 0x10) { // FCOMMENT, NUL-terminated
        while (pos < gz + gz_len && *pos) pos++;
        if (pos >= gz + gz_len) return -5;
        pos++;
    }
    if (flg & 0x02) { // FHCRC
        pos += 2;
    }

    if (pos > gz + gz_len - 8) return -6; // need deflate + CRC32 + ISIZE

    const uint8_t *trailer = gz + gz_len - 8;
    *deflate_start = pos;
    *deflate_len = (unsigned long)(trailer - pos);
    *out_len = (unsigned long)((uint32_t)trailer[4] | ((uint32_t)trailer[5] << 8) |
                               ((uint32_t)trailer[6] << 16) | ((uint32_t)trailer[7] << 24));
    return 0;
}

static void ensure_kconfig_loaded(void)
{
    if (kernel_config || kconfig_scan_done) return;

    int64_t off = start_preset.kconfig_offset;
    int64_t gz_len = start_preset.kconfig_size;
    kconfig_scan_done = 1;
    if (!off || !gz_len) return;
    if (off < 0 || gz_len < 0 || off > kernel_size || gz_len > kernel_size - off) {
        log_boot("kconfig: bad preset range, off=%lld, size=%lld, kernel=%lld\n", off, gz_len, kernel_size);
        return;
    }

    const uint8_t *gz = (const uint8_t *)(kernel_va + off);
    const uint8_t *deflate_start = NULL;
    unsigned long deflate_len = 0, out_len = 0;
    int rc = find_ikconfig_deflate(gz, gz_len, &deflate_start, &deflate_len, &out_len);
    if (rc) {
        log_boot("kconfig: gzip header parse failed, rc=%d\n", rc);
        return;
    }
    if (!deflate_len || !out_len || out_len > (4 * 1024 * 1024)) {
        log_boot("kconfig: bad sizes (deflate=%lu, out=%lu)\n", deflate_len, out_len);
        return;
    }

    char *buf = kp_malloc(out_len + 1);
    if (!buf) {
        log_boot("kconfig: malloc failed for %lu bytes\n", out_len + 1);
        return;
    }

    unsigned long destlen = out_len;
    unsigned long sourcelen = deflate_len;
    rc = puff((unsigned char *)buf, &destlen, deflate_start, &sourcelen);
    if (rc != 0) {
        log_boot("kconfig: puff failed, rc=%d\n", rc);
        kp_free(buf);
        return;
    }

    buf[destlen] = 0;
    kernel_config = buf;
    kernel_config_size = (int32_t)destlen;
    log_boot("kconfig inflated from IKCFG, size: %lu -> %d\n", deflate_len, kernel_config_size);
}

int on_each_extra_item(int (*callback)(const patch_extra_item_t *extra, const char *arg, const void *con, void *udata),
                       void *udata)
{
    int rc = 0;
    uint64_t item_addr = _kp_extra_start;
    while (item_addr < _kp_extra_end) {
        patch_extra_item_t *item = (patch_extra_item_t *)item_addr;
        if (item->type == EXTRA_TYPE_NONE) break;
        if (lib_memcmp(item->magic, EXTRA_HDR_MAGIC, sizeof(item->magic))) break;
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

int has_preset_superkey()
{
    return superkey_is_user_set || root_superkey_is_set;
}

void predata_init()
{
    superkey = (char *)start_preset.superkey;
    root_superkey = (char *)start_preset.root_superkey;
    superkey_is_user_set = lib_strnlen(superkey, SUPER_KEY_LEN) > 0;
    root_superkey_is_set = *(uint64_t *)root_superkey;
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
    if (!superkey_is_user_set) {
        enable_root_key = true;
        int len = SUPER_KEY_LEN > 16 ? 16 : SUPER_KEY_LEN;
        len--;
        for (int i = 0; i < len; ++i) {
            uint64_t rand = rand_next() % (sizeof(bstr) - 1);
            superkey[i] = bstr[rand];
        }
    }

    patch_config = &start_preset.patch_config;

    // kconfig is loaded lazily on first kp_kconfig_*() call (by a KPM, well
    // after the kernel is up). Loading here in predata_init ran during the
    // paging_init hook where the console/page tables aren't ready; a data
    // abort there panics with no kmsg.

    for (uintptr_t addr = (uint64_t)patch_config; addr < (uintptr_t)patch_config + PATCH_CONFIG_LEN;
         addr += sizeof(uintptr_t)) {
        uintptr_t *p = (uintptr_t *)addr;
        if (*p) *p += kernel_va;
    }

#ifdef CONFIG_X86_64
    barrier();
#else
    dsb(ish);
#endif
}
