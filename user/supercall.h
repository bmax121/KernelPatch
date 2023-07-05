#ifndef _KPU_SUPERCALL_H_
#define _KPU_SUPERCALL_H_

#include <unistd.h>

#define SUPER_KEY_LEN 32

#if defined(ANDROID) || defined(SECCOMP_NOT_ALLOW_COMPACT)
#define __NR_supercall __NR_truncate
#else
#define __NR_supercall 0xff
#endif

#define SUPERCALL_HELLO 0x1000
#define SUPERCALL_GET_KERNEL_VERSION 0x1001
#define SUPERCALL_GET_KP_VERSION 0x1002
#define SUPERCALL_LOAD_KPM 0x1003
#define SUPERCALL_UNLOAD_KPM 0x1004
#define SUPERCALL_SU 0x1005
#define SUPERCALL_GRANT_SU 0x1006
#define SUPERCALL_REVOKE_SU 0x1007

#define SUPERCALL_CMD_TEST 0x10FF
#define SUPERCALL_CMD_MAX 0x1100

#define SUPERCALL_RES_SUCCEED 0
#define SUPERCALL_RES_FAILED 1
#define SUPERCALL_RES_NOT_IMPL 2

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

static inline long sc_test(const char *key)
{
    long ret = syscall(__NR_supercall, key, SUPERCALL_CMD_TEST);
    return ret;
}

#endif