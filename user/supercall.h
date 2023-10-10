#ifndef _KPU_SUPERCALL_H_
#define _KPU_SUPERCALL_H_

#include "uapi/scdefs.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static inline long sc_hello(const char *key)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_HELLO);
    return ret;
}

static inline bool sc_ready(const char *key)
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

static inline long sc_su(const char *key, const char *sctx)
{
    // todo: error code
    if (sctx && strlen(sctx) > SUPERCALL_SCONTEXT_LEN) {
        return -1;
    }
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU, sctx);
    return ret;
}

static inline long sc_thread_su(const char *key, pid_t pid, const char *sctx)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_THREAD_SU, pid, sctx);
    return ret;
}

static inline long sc_thread_unsu(const char *key, pid_t pid)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_THREAD_UNSU, pid);
    return ret;
}

#ifdef ANDROID
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

static inline long sc_list_su_allow(const char *key, uid_t *uids, size_t *size)
{
    // todo: size enough
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_LIST_SU_ALLOW, uids, size);
    return ret;
}

static inline long sc_reset_su_cmd(const char *key, const char *path)
{
    // todo: error code
    if (strlen(path) > SUPERCALL_SU_CMD_LEN) {
        return -1;
    }
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_RESET_SU_CMD, path);
    return ret;
}

#endif

#endif