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

static long call_grant_su(uid_t uid)
{
    return add_allow_uid(uid);
}

static long call_revoke_su(uid_t uid)
{
    return remove_allow_uid(uid);
}

static long call_list_su_allow(uid_t *__user uids, size_t *__user size)
{
    return list_allow_uids(uids, size);
}

long supercall_android(long cmd, void *__user arg1, void *__user arg2, void *__user arg3)
{
    long ret;
    if (cmd == SUPERCALL_GRANT_SU) {
        uid_t uid = (uid_t)(uintptr_t)arg1;
        ret = call_grant_su(uid);
    } else if (cmd == SUPERCALL_REVOKE_SU) {
        uid_t uid = (uid_t)(uintptr_t)arg1;
        ret = call_revoke_su(uid);
    } else if (cmd == SUPERCALL_LIST_SU_ALLOW) {
        uid_t *uids = (uid_t *)arg1;
        size_t *size = (size_t *)arg2;
        ret = call_list_su_allow(uids, size);
    } else {
        ret = SUPERCALL_RES_NOT_IMPL;
    }
    return ret;
}
