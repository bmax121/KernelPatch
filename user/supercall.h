#ifndef _KPU_SUPERCALL_H_
#define _KPU_SUPERCALL_H_

#include "uapi/scdefs.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

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

static inline long sc_load_kpm(const char *key, const char *path, const char *args)
{
    if (!path || strlen(path) <= 0) return EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_LOAD_KPM, path, args);
    return ret;
}

static inline long sc_unload_kpm(const char *key, const char *name)
{
    if (!name || strlen(name) <= 0) return EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_UNLOAD_KPM, name);
    return ret;
}

static inline long sc_kpm_nums(const char *key)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_KPM_NUMS);
    return ret;
}

static inline long sc_kpm_info(const char *key, int index, char *buf, int buf_len)
{
    if (!buf || buf_len <= 0) return EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_KPM_INFO, index, buf, buf_len);
    return ret;
}

static inline long sc_su(const char *key, const char *sctx)
{
    if (sctx && strlen(sctx) >= SUPERCALL_SCONTEXT_LEN) return EINVAL;
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

static inline long sc_num_su(const char *key)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_ALLOW_NUM);
    return ret;
}

static inline long sc_list_su_allow(const char *key, uid_t *uids, int uid_cap)
{
    if (!uids || uid_cap <= 0) return EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_LIST_SU_ALLOW, uids, uid_cap);
    return ret;
}

static inline long sc_su_reset_path(const char *key, const char cmd[SUPERCALL_SU_PATH_LEN])
{
    if (!cmd) return EINVAL;
    if (strlen(cmd) >= SUPERCALL_SU_PATH_LEN) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_RESET_PATH, cmd);
    return ret;
}

static inline long sc_su_get_path(const char *key, char out_path[SUPERCALL_SU_PATH_LEN], int size)
{
    if (!out_path || size <= 0) return EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_GET_PATH, out_path, size);
    return ret;
}

#endif

#endif