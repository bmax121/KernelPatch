#include "kpatch.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/capability.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

#include "supercall.h"

uint32_t version()
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return version_code;
}

uint32_t hello(const char *key)
{
    long ret = sc_hello(key);
    if (ret == SUPERCALL_HELLO_MAGIC) {
        fprintf(stdout, "%s\n", SUPERCALL_HELLO_ECHO);
        ret = 0;
    }
    return (uint32_t)ret;
}

uint32_t kpv(const char *key)
{
    long kpv = sc_kp_version(key);
    if (kpv < 0) return kpv;
    fprintf(stdout, "%x\n", (uint32_t)kpv);
    return 0;
}

int __test(const char *key)
{
    return __sc_test(key);
}
