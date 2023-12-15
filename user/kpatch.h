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

    uint32_t hello(const char *key);
    uint32_t kpv(const char *key);

    int su_fork(const char *key, uid_t uid, const char *sctx);
    int su_thread(const char *key, uid_t uid, uid_t to_uid, const char *sctx);

    int kpm_load(const char *key, const char *path, const char *args);
    int kpm_unload(const char *key, const char *name);
    int kpm_nums(const char *key);
    int kpm_list(const char *key);
    int kpm_info(const char *key, const char *name);
    int __test(const char *key);

    int su_grant(const char *key, uid_t uid, uid_t to_uid, const char *scontext);
    int su_revoke(const char *key, uid_t uid);
    int su_nums(const char *key);
    int su_list(const char *key);
    int su_reset_path(const char *key, const char *path);
    int su_get_path(const char *key);
    int android_user_init(const char *key);

#ifdef __cplusplus
}
#endif

#endif
