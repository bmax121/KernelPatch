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
#include <uapi/asm-generic/errno.h>

long supercall_android(long cmd, long arg1, long arg2, long arg3)
{
    long ret;
    if (cmd == SUPERCALL_GRANT_SU) {
        uid_t uid = (uid_t)(uintptr_t)arg1;
        ret = su_add_allow_uid(uid);
    } else if (cmd == SUPERCALL_REVOKE_SU) {
        uid_t uid = (uid_t)(uintptr_t)arg1;
        ret = su_remove_allow_uid(uid);
    } else if (cmd == SUPERCALL_SU_ALLOW_NUM) {
        ret = su_allow_uid_nums();
    } else if (cmd == SUPERCALL_LIST_SU_ALLOW) {
        uid_t *uids = (uid_t *)arg1;
        int num = (int)arg2;
        ret = su_list_allow_uids(uids, num);
    } else if (cmd == SUPERCALL_SU_RESET_PATH) {
        char cmd[SUPERCALL_SU_PATH_LEN] = { '\0' };
        strncpy_from_user_nofault(cmd, (char *__user)arg1, sizeof(cmd));
        ret = su_reset_path(cmd);
    } else if (cmd == SUPERCALL_SU_GET_PATH) {
        int size = (int)arg2;
        ret = su_get_path((char *)arg1, size);
    } else {
        ret = -ENOSYS;
    }
    return ret;
}
