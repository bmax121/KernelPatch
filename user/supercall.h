#ifndef _KPU_SUPERCALL_H_
#define _KPU_SUPERCALL_H_

#include <unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

#include "uapi/scdefs.h"

static inline long sc_hello(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_HELLO);
    return ret;
}

static inline bool sc_ready(const char *key)
{
    return sc_hello(key) == SUPERCALL_HELLO_MAGIC;
}

static inline long sc_klog(const char *key, const char *msg)
{
    if (!key || !key[0]) return -EINVAL;
    if (!msg || strlen(msg) <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_KLOG, msg);
    return ret;
}

static inline long sc_kp_version(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_KP_VERSION);
    return ret;
}

static inline long sc_su(const char *key, struct su_profile *profile)
{
    if (!key || !key[0]) return -EINVAL;
    if (strlen(profile->scontext) >= SUPERCALL_SCONTEXT_LEN) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU, profile);
    return ret;
}

static inline long sc_su_task(const char *key, pid_t tid, struct su_profile *profile)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_TASK, tid, profile);
    return ret;
}

static inline long sc_kpm_load(const char *key, const char *path, const char *args)
{
    if (!key || !key[0]) return -EINVAL;
    if (!path || strlen(path) <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_KPM_LOAD, path, args);
    return ret;
}

static inline long sc_kpm_unload(const char *key, const char *name)
{
    if (!key || !key[0]) return -EINVAL;
    if (!name || strlen(name) <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_KPM_UNLOAD, name);
    return ret;
}

static inline long sc_kpm_nums(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_KPM_NUMS);
    return ret;
}

static inline long sc_kpm_list(const char *key, char *names_buf, int buf_len)
{
    if (!key || !key[0]) return -EINVAL;
    if (!names_buf || buf_len <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_KPM_LIST, names_buf, buf_len);
    return ret;
}

static inline long sc_kpm_info(const char *key, const char *name, char *buf, int buf_len)
{
    if (!key || !key[0]) return -EINVAL;
    if (!buf || buf_len <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_KPM_INFO, name, buf, buf_len);
    return ret;
}

static inline long __sc_test(const char *key)
{
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_TEST);
    return ret;
}

#ifdef ANDROID
static inline long sc_su_grant_uid(const char *key, uid_t uid, struct su_profile *profile)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_GRANT_UID, uid, profile);
    return ret;
}

static inline long sc_su_revoke_uid(const char *key, uid_t uid)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_REVOKE_UID, uid);
    return ret;
}

static inline long sc_su_uid_nums(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_NUMS);
    return ret;
}

static inline long sc_su_allow_uids(const char *key, uid_t *buf, int num)
{
    if (!key || !key[0]) return -EINVAL;
    if (!buf || num <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_LIST, buf, num);
    return ret;
}

static inline long sc_su_uid_profile(const char *key, uid_t uid, struct su_profile *out_profile)
{
    if (!key || !key[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_PROFILE, uid, out_profile);
    return ret;
}

static inline long sc_su_reset_path(const char *key, const char *path)
{
    if (!key || !key[0]) return -EINVAL;
    if (!path || !path[0]) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_RESET_PATH, path);
    return ret;
}

static inline long sc_su_get_path(const char *key, char *buf, int buf_size)
{
    if (!key || !key[0]) return -EINVAL;
    if (!buf || buf_size <= 0) return -EINVAL;
    long ret = syscall(__NR_supercall, key, hash_key(key), SUPERCALL_SU_GET_PATH, buf, buf_size);
    return ret;
}

#endif

#endif