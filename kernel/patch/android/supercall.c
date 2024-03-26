/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
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
#include <linux/err.h>
#include <linux/slab.h>
#include <uapi/asm-generic/errno.h>

static long call_grant_uid(uid_t uid, struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    int rc = su_add_allow_uid(uid, profile, 1);
    kvfree(profile);
    return rc;
}

static long call_revoke_uid(uid_t uid)
{
    return su_remove_allow_uid(uid, 1);
}

static long call_su_allow_uid_nums()
{
    return su_allow_uid_nums();
}

static long call_su_list_allow_uid(uid_t *__user uids, int num)
{
    return su_allow_uids(uids, num);
}

static long call_su_allow_uid_profile(uid_t uid, struct su_profile *__user uprofile)
{
    return su_allow_uid_profile(uid, uprofile);
}

static long call_reset_su_path(const char *__user upath)
{
    char path[SU_PATH_MAX_LEN];
    compat_strncpy_from_user(path, upath, sizeof(path));
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
        return call_grant_uid((uid_t)arg1, (struct su_profile * __user) arg2);
    case SUPERCALL_SU_REVOKE_UID:
        return call_revoke_uid((uid_t)arg1);
    case SUPERCALL_SU_NUMS:
        return call_su_allow_uid_nums();
    case SUPERCALL_SU_LIST:
        return call_su_list_allow_uid((uid_t *)arg1, (int)arg2);
    case SUPERCALL_SU_PROFILE:
        return call_su_allow_uid_profile((uid_t)arg1, (struct su_profile * __user) arg2);
    case SUPERCALL_SU_RESET_PATH:
        return call_reset_su_path((const char *)arg1);
    case SUPERCALL_SU_GET_PATH:
        return call_su_get_path((char *__user)arg1, (int)arg2);
    default:
        break;
    }
    return -ENOSYS;
}
