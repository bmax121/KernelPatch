#ifndef _KPU_LIBKP_H_
#define _KPU_LIBKP_H_

#include "supercall.h"
#include "version"

static inline uint32_t get_version()
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return version_code;
}

long su_fork(const char *key, const char *sctx);

#endif
