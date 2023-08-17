#ifndef _KPU_SUPERCALL_H_
#define _KPU_SUPERCALL_H_

#include "uapi/scdefs.h"

#include <unistd.h>
#include <sys/syscall.h>

static inline long sc_hello(const char *key)
{
    long ret = syscall(__NR_supercall, key, SUPERCALL_HELLO);
    return ret;
}

static inline long sc_get_kernel_version(const char *key)
{
    long ret = syscall(__NR_supercall, key, SUPERCALL_GET_KERNEL_VERSION);
    return ret;
}

static inline long sc_get_kp_version(const char *key)
{
    long ret = syscall(__NR_supercall, key, SUPERCALL_GET_KP_VERSION);
    return ret;
}

static inline long sc_load_kpm(const char *key, const char *path)
{
    long ret = syscall(__NR_supercall, key, SUPERCALL_LOAD_KPM, path);
    return ret;
}

static inline long sc_unload_kpm(const char *key, const char *path)
{
    long ret = syscall(__NR_supercall, key, SUPERCALL_UNLOAD_KPM, path);
    return ret;
}

static inline long sc_su(const char *key)
{
    long ret = syscall(__NR_supercall, key, SUPERCALL_SU);
    return ret;
}

static inline long sc_grant_su(const char *key, pid_t pid)
{
    long ret = syscall(__NR_supercall, key, SUPERCALL_GRANT_SU, pid);
    return ret;
}

static inline long sc_revoke_su(const char *key, pid_t pid)
{
    long ret = syscall(__NR_supercall, key, SUPERCALL_REVOKE_SU, pid);
    return ret;
}

#endif