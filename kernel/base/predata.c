#include <predata.h>
#include <common.h>
#include <log.h>

#include "start.h"

static char superkey[SUPER_KEY_LEN] = { '\0' };
static int32_t superkey_len = 0;

int superkey_auth(const char *key, int32_t len)
{
    if (!key || len <= 0 || superkey_len != len) return -1;
    for (int i = 0; i < len; i++) {
        if (superkey[i] != key[i]) return -1;
    }
    return 0;
}

int predata_init()
{
    for (int32_t i = 0; i < SUPER_KEY_LEN; i++) {
        char c = start_preset.superkey[i];
        if (!c) {
            superkey_len = i;
            break;
        }
        superkey[i] = c;
    }
    logki("Preset super key: %s\n", superkey);
    return 0;
}