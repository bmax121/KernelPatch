/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KPU_KPATCH_H_
#define _KPU_KPATCH_H_

#include <stdint.h>
#include <unistd.h>
#include "../version"

#ifdef __cplusplus
extern "C"
{
#endif

    uint32_t version();

    void hello(const char *key);
    void kpv(const char *key);
    void kv(const char *key);

    int skey_main(int argc, char **argv);

    void bootlog(const char *key);
    void panic(const char *key);
    int __test(const char *key);

#ifdef __cplusplus
}
#endif

#endif
