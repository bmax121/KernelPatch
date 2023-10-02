#ifndef _KPU_LIBKP_H_
#define _KPU_LIBKP_H_

#include "supercall.h"
#include "version"

uint32_t get_version();
long su_fork(const char *key, const char *sctx);

#endif
