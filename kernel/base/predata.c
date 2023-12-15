#include <predata.h>
#include <common.h>
#include <log.h>

#include "start.h"

static char superkey[SUPER_KEY_LEN] = { '\0' };
static int superkey_len = 0;
static struct patch_config *patch_config = 0;

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

void predata_init(const char *skey, struct patch_config *config)
{
    for (int i = 0; i < SUPER_KEY_LEN - 1; i++) {
        char c = skey[i];
        if (!c) {
            superkey_len = i;
            break;
        }
        superkey[i] = c;
    }
    patch_config = config;
}