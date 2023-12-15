#ifndef _KP_PREDATA_H_
#define _KP_PREDATA_H_

#include <ktypes.h>
#include <stdbool.h>
#include <preset.h>

int superkey_auth(const char *key, int len);
const char *get_superkey();
struct patch_config *get_preset_patch_cfg();

void predata_init(const char *skey, struct patch_config *config);

#endif