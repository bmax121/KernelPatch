#ifndef _KPU_SUPERCALL_H_
#define _KPU_SUPERCALL_H_

#include "uapi/scdefs.h"

#include <unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>

static inline long sc_hello(const char *key)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_HELLO);
    return ret;
}

static inline bool installed(const char *key)
{
    return sc_hello(key) == SUPERCALL_HELLO_MAGIC;
}

static inline long sc_get_kernel_version(const char *key)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_GET_KERNEL_VERSION);
    return ret;
}

static inline long sc_get_kp_version(const char *key)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_GET_KP_VERSION);
    return ret;
}

static inline long sc_load_kpm(const char *key, const char *path)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_LOAD_KPM, path);
    return ret;
}

static inline long sc_unload_kpm(const char *key, const char *path)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_UNLOAD_KPM, path);
    return ret;
}

static inline long sc_su(const char *key)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU);
    return ret;
}

static inline long sc_grant_su(const char *key, uid_t uid)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_GRANT_SU, uid);
    return ret;
}

static inline long sc_revoke_su(const char *key, uid_t uid)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_REVOKE_SU, uid);
    return ret;
}

static inline long sc_thread_su(const char *key, pid_t pid)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_THREAD_SU, pid);
    return ret;
}

static inline long sc_thread_unsu(const char *key, pid_t pid)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_THREAD_UNSU, pid);
    return ret;
}

#endif