#include <predata.h>
#include <common.h>
#include <log.h>

#include "start.h"
#include "pgtable.h"

extern start_preset_t start_preset;

static char superkey[SUPER_KEY_LEN] = { '\0' };
static int superkey_len = 0;
static struct patch_config *patch_config = 0;
static struct patch_symbol *patch_symbol = 0;

int superkey_auth(const char *key, int len)
{
    if (!key || len <= 0 || superkey_len != len) return -1;
    for (int i = 0; i < len; i++) {
        if (superkey[i] != key[i]) return -1;
    }
    return 0;
}

const char *get_superkey()
{
    return superkey;
}

struct patch_config *get_preset_patch_cfg()
{
    return patch_config;
}

struct patch_symbol *get_preset_patch_sym()
{
    return patch_symbol;
}

void predata_init()
{
    for (int i = 0; i < SUPER_KEY_LEN - 1; i++) {
        char c = start_preset.superkey[i];
        if (!c) {
            superkey_len = i;
            break;
        }
        superkey[i] = c;
    }
    patch_symbol = &start_preset.patch_symbol;
    for (uintptr_t addr = (uint64_t)patch_symbol; addr < (uintptr_t)patch_symbol + PATCH_SYMBOL_LEN;
         addr += sizeof(uintptr_t)) {
        uintptr_t *p = (uintptr_t *)addr;
        if (*p) *p += kernel_va;
    }
    patch_config = &start_preset.patch_config;
}