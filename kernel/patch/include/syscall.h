#ifndef _KP_SYSCALL_H_
#define _KP_SYSCALL_H_

#include <asm/ptrace.h>
#include <ksyms.h>
#include <hook.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>

extern uintptr_t kvar_def(sys_call_table);
extern uintptr_t kvar_def(compat_sys_call_table);
extern bool syscall_has_wrapper;

const char __user *get_user_arg_ptr(void *a0, void *a1, int nr);

long raw_syscall0(long nr);
long raw_syscall1(long nr, long arg0);
long raw_syscall2(long nr, long arg0, long arg1);
long raw_syscall3(long nr, long arg0, long arg1, long arg2);
long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3);
long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4);
long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

#define raw_syscall(f) raw_syscall##f

static inline uint64_t *syscall_args(void *hook_fargs)
{
    uint64_t *args;
    if (syscall_has_wrapper) {
        args = ((struct pt_regs *)((hook_fargs0_t *)hook_fargs)->args[0])->regs;
    } else {
        args = ((hook_fargs0_t *)hook_fargs)->args;
    }
    return args;
}

static inline uint64_t syscall_argn(void *fdata_args, int n)
{
    return syscall_args(fdata_args)[n];
}

static inline void set_syscall_argn(void *fdata_args, int n, uint64_t val)
{
    uint64_t *args = syscall_args(fdata_args);
    args[n] = val;
}

static inline hook_err_t fp_hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    uintptr_t fp_addr = (uintptr_t)(kvar(sys_call_table) + nr);
    return fp_hook_wrap(fp_addr, narg, before, after, udata);
}

static inline void fp_unhook_syscall(int nr, void *before, void *after)
{
    uintptr_t fp_addr = (uintptr_t)(kvar(sys_call_table) + nr);
    fp_hook_unwrap(fp_addr, before, after);
}

static inline hook_err_t inline_hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    uintptr_t fp = kvar(sys_call_table)[nr];
    return hook_wrap((void *)fp, narg, before, after, udata);
}

static inline void inline_unhook_syscall(int nr, void *before, void *after)
{
    uintptr_t fp = kvar(sys_call_table)[nr];
    hook_unwrap((void *)fp, before, after);
}

int syscall_init();

#endif