#include "kpatch.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/capability.h>
#include <errno.h>

#include "version"

uint32_t get_version()
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return version_code;
}

long su_fork(const char *key, const char *sctx)
{
    long ret = 0;
    ret = sc_su(key, sctx);
    if (!ret || ret == -EINVAL) execlp("sh", "", NULL);
    return ret;
}
