#include "scdefs.h"

#include <hook.h>
#include <common.h>
#include <log.h>
#include <predata.h>
#include <pgtable.h>
#include <syscall.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <accctl/accctl.h>

#define MAX_KEY_LEN 128

static inline long call_hello()
{
    logki("Kernel Supercall Hello!\n");
    return SUPERCALL_RES_SUCCEED;
}

static inline long call_get_kernel_version()
{
    return kver;
}

static inline long call_get_kp_version()
{
    return kpver;
}

static long call_load_kpm(const char *path, long len)
{
    return SUPERCALL_RES_NOT_IMPL;
}

static long call_unload_kpm(const char *path, long len)
{
    return SUPERCALL_RES_NOT_IMPL;
}

static inline long call_su()
{
    int ret = SUPERCALL_RES_SUCCEED;
    ret = commit_su();
    return ret;
}

static long call_grant_su(pid_t pid)
{
    int ret = SUPERCALL_RES_SUCCEED;
    ret = grant_su(pid, true);
    return ret;
}

static long call_revoke_su(pid_t pid)
{
    return SUPERCALL_RES_NOT_IMPL;
}

static long call_test()
{
    int ret = SUPERCALL_RES_SUCCEED;
    void _log_current_whites();
    return ret;
}

long supercall(const char __user *key, long cmd, long arg2, long arg3, long arg4, long arg5)
{
    long ret = SUPERCALL_RES_SUCCEED;
    if (cmd == SUPERCALL_HELLO) {
        ret = call_hello();
    } else if (cmd == SUPERCALL_GET_KERNEL_VERSION) {
        ret = kver;
    } else if (cmd == SUPERCALL_GET_KP_VERSION) {
        ret = kpver;
    } else if (cmd == SUPERCALL_LOAD_KPM) {
        ret = call_load_kpm(0, 0);
    } else if (cmd == SUPERCALL_UNLOAD_KPM) {
        ret = call_unload_kpm(0, 0);
    } else if (cmd == SUPERCALL_SU) {
        ret = call_su();
    } else if (cmd == SUPERCALL_GRANT_SU) {
        pid_t pid = (pid_t)arg2;
        ret = call_grant_su(pid);
    } else if (cmd == SUPERCALL_REVOKE_SU) {
        pid_t pid = (pid_t)arg2;
        ret = call_revoke_su(pid);
    } else if (cmd == SUPERCALL_TEST) {
        uid_t uid = (uid_t)arg2;
        ret = call_test(uid);
    } else {
        ret = SUPERCALL_RES_NOT_IMPL;
    }
    return ret;
}

HOOK_SYSCALL_DEFINE6(__NR_supercall, const char __user *, ukey, long, cmd, long, a2, long, a3, long, a4, long, a5)
{
    char key[MAX_KEY_LEN] = { '\0' };
    long len = strncpy_from_user(key, ukey, MAX_KEY_LEN);
    if (superkey_auth(key, len)) { return HOOK_SYSCALL_CALL_ORIGIN(__NR_supercall, ukey, cmd, a2, a3, a4, a5); }
    logkd("SuperCall cmd: %x, a2: %x, a3: %x, a4: %x, a5: %x\n", cmd, a2, a3, a4, a5);
    return supercall(key, cmd, a2, a3, a4, a5);
}

int supercall_init()
{
    // REPLACE_SYSCALL_INSTALL(__NR_supercall);
    INLINE_SYSCALL_INSTALL(__NR_supercall);
    return 0;
}
