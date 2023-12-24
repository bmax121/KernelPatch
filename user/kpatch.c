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

void hello(const char *key)
{
    long ret = sc_hello(key);
    if (ret == SUPERCALL_HELLO_MAGIC) {
        fprintf(stdout, "%s\n", SUPERCALL_HELLO_ECHO);
    }
}

void kpv(const char *key)
{
    uint32_t kpv = sc_kp_ver(key);
    fprintf(stdout, "%x\n", kpv);
}

void kv(const char *key)
{
    uint32_t kv = sc_k_ver(key);
    fprintf(stdout, "%x\n", kv);
}

int __test(const char *key)
{
    return __sc_test(key);
}
