/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_SYSCALL_H_
#define _KP_SYSCALL_H_

#include <asm/ptrace.h>
#include <ksyms.h>
#include <hook.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>

extern int has_syscall_wrapper;
extern struct
{
    const char *name;
    uintptr_t addr;
} syscall_name_table[460];

extern struct
{
    const char *name;
    uintptr_t addr;
} compat_syscall_name_table[460];

const char __user *get_user_arg_ptr(void *a0, void *a1, int nr);

int set_user_arg_ptr(void *a0, void *a1, int nr, uintptr_t val);

long raw_syscall0(long nr);
long raw_syscall1(long nr, long arg0);
long raw_syscall2(long nr, long arg0, long arg1);
long raw_syscall3(long nr, long arg0, long arg1, long arg2);
long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3);
long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4);
long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

#define raw_syscall(f) raw_syscall##f

uintptr_t syscalln_name_addr(int nr, int is_compat);

uintptr_t syscalln_addr(int nr, int is_compat);

static inline uint64_t *syscall_args(void *hook_fargs)
{
    uint64_t *args;
    if (has_syscall_wrapper) {
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

static inline void *syscall_argn_p(void *fdata_args, int n)
{
    return syscall_args(fdata_args) + n;
}

/**
 * @brief 
 * 
 * @param nr 
 * @param narg 
 * @param is_compat 
 * @param before 
 * @param after 
 * @param udata 
 * @return hook_err_t 
 */
hook_err_t fp_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata);

/**
 * @brief 
 * 
 * @param nr 
 * @param is_compat 
 * @param before 
 * @param after 
 */
void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after);

static inline hook_err_t fp_hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
}

static inline void fp_unhook_syscalln(int nr, void *before, void *after)
{
    return fp_unwrap_syscalln(nr, 0, before, after);
}

static inline hook_err_t fp_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    return fp_wrap_syscalln(nr, narg, 1, before, after, udata);
}

static inline void fp_unhook_compat_syscalln(int nr, void *before, void *after)
{
    return fp_unwrap_syscalln(nr, 1, before, after);
}

/**
 * @brief 
 * 
 * @param nr 
 * @param narg 
 * @param is_compat 
 * @param before 
 * @param after 
 * @param udata 
 * @return hook_err_t 
 */
hook_err_t inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata);

/**
 * @brief 
 * 
 * @param nr 
 * @param is_compat 
 * @param before 
 * @param after 
 */
void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after);

static inline hook_err_t inline_hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}

static inline void inline_unhook_syscalln(int nr, void *before, void *after)
{
    inline_unwrap_syscalln(nr, 0, before, after);
}

static inline hook_err_t inline_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    return inline_wrap_syscalln(nr, narg, 1, before, after, udata);
}

static inline void inline_unhook_compat_syscalln(int nr, void *before, void *after)
{
    inline_unwrap_syscalln(nr, 0, before, after);
}

//

hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata);

void unhook_syscalln(int nr, void *before, void *after);

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata);

void unhook_compat_syscalln(int nr, void *before, void *after);

#endif