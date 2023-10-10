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

static inline long call_su(const char *sctx)
{
    int ret = commit_su(1, sctx);
    return ret;
}

static long call_thread_su(pid_t pid, const char *sctx)
{
    int ret = SUPERCALL_RES_SUCCEED;
    ret = thread_su(pid, sctx);
    return ret;
}

static long call_thread_unsu(pid_t pid)
{
    return SUPERCALL_RES_NOT_IMPL;
}

static long supercall(long cmd, void *__user arg1, void *__user arg2, void *__user arg3)
{
    logkd("SuperCall with cmd: %x\n", cmd);

    long ret = SUPERCALL_RES_NOT_IMPL;

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
        char sctx[SUPERCALL_SCONTEXT_LEN + 1];
        sctx[SUPERCALL_SCONTEXT_LEN] = 0;
        long len = strncpy_from_user(sctx, (const char *)arg1, SUPERCALL_SCONTEXT_LEN);
        ret = call_su(len > 0 ? sctx : 0);
    } else if (cmd == SUPERCALL_THREAD_SU) {
        pid_t pid = (pid_t)(uintptr_t)arg1;
        char sctx[SUPERCALL_SCONTEXT_LEN + 1];
        sctx[SUPERCALL_SCONTEXT_LEN] = 0;
        long len = strncpy_from_user(sctx, (const char *)arg2, SUPERCALL_SCONTEXT_LEN);
        ret = call_thread_su(pid, len > 0 ? sctx : 0);
    } else if (cmd == SUPERCALL_THREAD_UNSU) {
        pid_t pid = (pid_t)(uintptr_t)arg1;
        ret = call_thread_unsu(pid);
    } else {
#ifdef ANDROID
        ret = supercall_android(cmd, arg1, arg2, arg3);
#else
        ret = SUPERCALL_RES_NOT_IMPL;
#endif
    }
    return ret;
}

HOOK_SYSCALL_DEFINE6(__NR_supercall, const char __user *, ukey, long, hash, long, cmd, void *, a1, void *, a2, void *,
                     a3)
{
    char key[MAX_KEY_LEN + 1] = { '\0' };
    long len = strncpy_from_user(key, ukey, MAX_KEY_LEN);

    if (len <= 0) {
        goto ori_call;
    }

    if (cmd >= SUPERCALL_MAX || cmd < SUPERCALL_HELLO) {
        goto ori_call;
    }

    if (superkey_auth(key, len)) {
        goto ori_call;
    }

    if (hash_key(key) != hash) {
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
