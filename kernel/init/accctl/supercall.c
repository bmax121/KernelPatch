#include <uapi/scdefs.h>
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
#include <accctl.h>

#define MAX_KEY_LEN 127

static inline long call_hello()
{
    logki("KernelPatch Supercall Hello!\n");
    return SUPERCALL_HELLO_MAGIC;
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
    int ret = commit_su();
    return ret;
}

static long call_grant_su(uid_t uid)
{
    return SUPERCALL_RES_NOT_IMPL;
}

static long call_revoke_su(uid_t uid)
{
    return SUPERCALL_RES_NOT_IMPL;
}

static long call_thread_su(pid_t pid)
{
    int ret = SUPERCALL_RES_SUCCEED;
    ret = thread_su(pid, true);
    return ret;
}

static long call_thread_unsu(pid_t pid)
{
    return SUPERCALL_RES_NOT_IMPL;
}

static long call_test()
{
    int ret = SUPERCALL_RES_SUCCEED;
    return ret;
}

static long supercall(long cmd, long arg1, long arg2, long arg3)
{
    logkd("SuperCall with cmd: %x, a1: %llx, a2: %llx, a3: %llx\n", cmd, arg1, arg2, arg3);

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
        uid_t uid = (uid_t)arg1;
        ret = call_grant_su(uid);
    } else if (cmd == SUPERCALL_REVOKE_SU) {
        uid_t uid = (uid_t)arg1;
        ret = call_revoke_su(uid);
    } else if (cmd == SUPERCALL_THREAD_SU) {
        pid_t pid = (pid_t)arg1;
        ret = call_thread_su(pid);
    } else if (cmd == SUPERCALL_THREAD_UNSU) {
        pid_t pid = (pid_t)arg1;
        ret = call_thread_unsu(pid);
    } else if (cmd == SUPERCALL_TEST) {
        ret = call_test();
    } else {
        ret = SUPERCALL_RES_NOT_IMPL;
    }
    return ret;
}

HOOK_SYSCALL_DEFINE6(__NR_supercall, const char __user *, ukey, long, hash, long, cmd, long, a1, long, a2, long, a3)
{
    char key[MAX_KEY_LEN + 1] = { '\0' };
    long len = strncpy_from_user(key, ukey, MAX_KEY_LEN);

    if (len <= 0) {
        goto ori_call;
    }

    if (hash_key(key) != hash) {
        goto ori_call;
    }

    if (cmd >= SUPERCALL_MAX || cmd < SUPERCALL_HELLO) {
        goto ori_call;
    }

    if (superkey_auth(key, len)) {
        goto ori_call;
    }

    return supercall(cmd, a1, a2, a3);

ori_call:
    return HOOK_SYSCALL_CALL_ORIGIN(__NR_supercall, ukey, hash, cmd, a1, a2, a3);
}

int supercall_install()
{
    // REPLACE_SYSCALL_INSTALL(__NR_supercall);
    INLINE_SYSCALL_INSTALL(__NR_supercall);
    return 0;
}
