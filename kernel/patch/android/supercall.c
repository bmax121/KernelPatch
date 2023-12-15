#include <uapi/scdefs.h>
#include <hook.h>
#include <common.h>
#include <log.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <accctl.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

static long call_grant_uid(uid_t uid, uid_t to_uid, const char *__user usctx)
{
    const char *sctx = 0;
    if (usctx) {
        char buf[SUPERCALL_SCONTEXT_LEN];
        int slen = strncpy_from_user_nofault(buf, usctx, sizeof(buf));
        if (slen > 0) sctx = buf;
    }
    return su_add_allow_uid(uid, to_uid, sctx, 1);
}

static long call_revoke_uid(uid_t uid)
{
    return su_remove_allow_uid(uid, 1);
}

static long call_su_allow_uid_nums()
{
    return su_allow_uid_nums();
}

static long call_su_list_allow_uid(char *__user buf, int buf_len)
{
    return su_list_allow_uids(buf, buf_len);
}

static long call_reset_su_path(const char *__user upath)
{
    char path[SU_PATH_MAX_LEN];
    strncpy_from_user_nofault(path, upath, sizeof(path));
    if (strlen(path) < SU_PATH_MIN_LEN - 1) return -EINVAL;
    return su_reset_path(path);
}

static long call_su_get_path(char *__user ubuf, int buf_len)
{
    return su_get_path(ubuf, buf_len);
}

long supercall_android(long cmd, long arg1, long arg2, long arg3)
{
    switch (cmd) {
    case SUPERCALL_SU_GRANT_UID:
        return call_grant_uid((uid_t)arg1, (uid_t)arg2, (const char *__user)arg3);
    case SUPERCALL_SU_REVOKE_UID:
        return call_revoke_uid((uid_t)arg1);
    case SUPERCALL_SU_ALLOW_UID_NUM:
        return call_su_allow_uid_nums();
    case SUPERCALL_SU_LIST_ALLOW_UID:
        return call_su_list_allow_uid((char *__user)arg1, (int)arg2);
    case SUPERCALL_SU_RESET_PATH:
        return call_reset_su_path((const char *)arg1);
    case SUPERCALL_SU_GET_PATH:
        return call_su_get_path((char *__user)arg1, (int)arg2);
    default:
        break;
    }
    return -ENOSYS;
}
