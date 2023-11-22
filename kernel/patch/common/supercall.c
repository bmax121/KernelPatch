#include <uapi/scdefs.h>
#include <hook.h>
#include <common.h>
#include <log.h>
#include <predata.h>
#include <pgtable.h>
#include <linux/syscall.h>
#include <uapi/asm-generic/errno.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <syscall.h>
#include <accctl.h>
#include <module.h>
#include <kputils.h>

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

static long call_load_kpm(const char __user *arg1, const char *__user arg2)
{
    char path[512], args[512];
    long pathlen = strncpy_from_user_nofault(path, arg1, sizeof(path));
    if (pathlen <= 0) return EINVAL;
    long arglen = strncpy_from_user_nofault(args, arg2, sizeof(args));
    return load_module_path(path, arglen <= 0 ? 0 : args);
}

static long call_unload_kpm(const char *__user arg1)
{
    char name[512];
    long len = strncpy_from_user_nofault(name, arg1, sizeof(name));
    if (len <= 0) return EINVAL;
    return unload_module(name);
}

static long call_kpm_nums()
{
    return get_module_nums();
}

static long call_kpm_info(int index, char *__user out_info, int out_len)
{
    if (index < 0) return 0;
    if (out_len <= 0) return 0;
    char buf[1024];
    int sz = get_module_info(index, buf, sizeof(buf));
    if (sz <= 0) return sz;
    if (sz > out_len) return -ENOMEM;
    sz = seq_copy_to_user(out_info, buf, sz);
    return sz;
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
    return -ENOSYS;
}

static long supercall(long cmd, long arg1, long arg2, long arg3)
{
    logkd("supercall with cmd: %x\n", cmd);

    long ret = -ENOSYS;

    if (cmd == SUPERCALL_HELLO) {
        ret = call_hello();
    } else if (cmd == SUPERCALL_GET_KERNEL_VERSION) {
        ret = kver;
    } else if (cmd == SUPERCALL_GET_KP_VERSION) {
        ret = kpver;
    } else if (cmd == SUPERCALL_LOAD_KPM) {
        ret = call_load_kpm((const char *__user)arg1, (const char *__user)arg2);
    } else if (cmd == SUPERCALL_UNLOAD_KPM) {
        ret = call_unload_kpm((const char *__user)arg1);
    } else if (cmd == SUPERCALL_KPM_NUMS) {
        return call_kpm_nums();
    } else if (cmd == SUPERCALL_KPM_INFO) {
        return call_kpm_info((long)arg1, (char *__user)arg2, (long)arg3);
    } else if (cmd == SUPERCALL_SU) {
        char sctx[SUPERCALL_SCONTEXT_LEN];
        long len = strncpy_from_user_nofault(sctx, (const char *)arg1, SUPERCALL_SCONTEXT_LEN);
        ret = call_su(len > 0 ? sctx : 0);
    } else if (cmd == SUPERCALL_THREAD_SU) {
        pid_t pid = (pid_t)(uintptr_t)arg1;
        char sctx[SUPERCALL_SCONTEXT_LEN];
        long len = strncpy_from_user_nofault(sctx, (char *)arg2, SUPERCALL_SCONTEXT_LEN);
        ret = call_thread_su(pid, len > 0 ? sctx : 0);
    } else if (cmd == SUPERCALL_THREAD_UNSU) {
        pid_t pid = (pid_t)(uintptr_t)arg1;
        ret = call_thread_unsu(pid);
    } else {
#ifdef ANDROID
        ret = supercall_android(cmd, arg1, arg2, arg3);
#else
        ret = -ENOSYS;
#endif
    }
    return ret;
}

void before(hook_fargs6_t *args, void *udata)
{
    const char *__user ukey;
    long hash;
    long cmd;
    long a1;
    long a2;
    long a3;

    if (syscall_has_wrapper) {
        const struct pt_regs *regs = (const struct pt_regs *)args->arg0;
        ukey = (const char *__user)regs->regs[0];
        hash = (long)regs->regs[1];
        cmd = (long)regs->regs[2];
        a1 = (long)regs->regs[3];
        a2 = (long)regs->regs[4];
        a3 = (long)regs->regs[5];
    } else {
        ukey = (const char *__user)args->arg0;
        hash = (long)args->arg1;
        cmd = (long)args->arg2;
        a1 = (long)args->arg3;
        a2 = (long)args->arg4;
        a3 = (long)args->arg5;
    }

    char key[MAX_KEY_LEN + 1];
    long len = strncpy_from_user_nofault(key, ukey, MAX_KEY_LEN + 1);

    if (len <= 0) return;
    if (cmd >= SUPERCALL_MAX || cmd < SUPERCALL_HELLO) return;
    if (superkey_auth(key, len - 1)) return;
    if (hash_key(key) != hash) return;

    args->early_ret = 1;
    args->ret = supercall(cmd, a1, a2, a3);
}

int supercall_install()
{
    int rc = 0;
    // hook_err_t err = inline_hook_syscalln(__NR_supercall, 6, before, 0, 0);
    hook_err_t err = fp_hook_syscalln(__NR_supercall, 6, before, 0, 0);
    if (err) {
        log_boot("install supercall hook error: %d\n", err);
        rc = err;
        goto out;
    }
out:
    return rc;
}
