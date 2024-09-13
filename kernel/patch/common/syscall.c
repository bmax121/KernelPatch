/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "syscall.h"

#include <cache.h>
#include <ktypes.h>
#include <hook.h>
#include <common.h>
#include <linux/string.h>
#include <symbol.h>
#include <uapi/asm-generic/errno.h>
#include <asm-generic/compat.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <predata.h>
#include <kputils.h>
#include <linux/kernel.h>
#include <linux/string.h>

uintptr_t *sys_call_table = 0;
KP_EXPORT_SYMBOL(sys_call_table);

uintptr_t *compat_sys_call_table = 0;
KP_EXPORT_SYMBOL(compat_sys_call_table);

int has_syscall_wrapper = 0;
KP_EXPORT_SYMBOL(has_syscall_wrapper);

int has_config_compat = 0;
KP_EXPORT_SYMBOL(has_config_compat);

struct user_arg_ptr
{
    union
    {
        const char __user *const __user *native;
    } ptr;
};

struct user_arg_ptr_compat
{
    bool is_compat;
    union
    {
        const char __user *const __user *native;
        const compat_uptr_t __user *compat;
    } ptr;
};

// actually, a0 is true if it is compat
const char __user *get_user_arg_ptr(void *a0, void *a1, int nr)
{
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) size = 4; // compat
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    char __user **upptr = memdup_user(native, size);
    if (IS_ERR(upptr)) return ERR_PTR((long)upptr);

    char __user *uptr;
    if (size == 8) {
        uptr = *upptr;
    } else {
        uptr = (char __user *)(unsigned long)*(int32_t *)upptr;
    }
    kfree(upptr);
    return uptr;
}

int set_user_arg_ptr(void *a0, void *a1, int nr, uintptr_t val)
{
    uintptr_t valp = (uintptr_t)&val;
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) {
            size = 4; // compat
            valp += 4;
        }
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    int cplen = compat_copy_to_user((void *)native, (void *)valp, size);
    return cplen == size ? 0 : cplen;
}

typedef long (*warp_raw_syscall_f)(const struct pt_regs *regs);
typedef long (*raw_syscall0_f)();
typedef long (*raw_syscall1_f)(long arg0);
typedef long (*raw_syscall2_f)(long arg0, long arg1);
typedef long (*raw_syscall3_f)(long arg0, long arg1, long arg2);
typedef long (*raw_syscall4_f)(long arg0, long arg1, long arg2, long arg3);
typedef long (*raw_syscall5_f)(long arg0, long arg1, long arg2, long arg3, long arg4);
typedef long (*raw_syscall6_f)(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

uintptr_t syscalln_name_addr(int nr, int is_compat)
{
    const char *name = 0;
    if (!is_compat) {
        if (syscall_name_table[nr].addr) {
            return syscall_name_table[nr].addr;
        }
        name = syscall_name_table[nr].name;
    } else {
        if (compat_syscall_name_table[nr].addr) {
            return compat_syscall_name_table[nr].addr;
        }
        name = compat_syscall_name_table[nr].name;
    }

    if (!name) return 0;

    const char *prefix[2];
    prefix[0] = "__arm64_";
    prefix[1] = "";
    const char *suffix[3];
    suffix[0] = ".cfi_jt";
    suffix[1] = ".cfi";
    suffix[2] = "";

    uintptr_t addr = 0;

    char buffer[256];
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            snprintf(buffer, sizeof(buffer), "%s%s%s", prefix[i], name, suffix[j]);
            addr = kallsyms_lookup_name(buffer);
            if (addr) break;
        }
        if (addr) break;
    }
    if (!is_compat) {
        syscall_name_table[nr].addr = addr;
    } else {
        compat_syscall_name_table[nr].addr = addr;
    }
    return addr;
}
KP_EXPORT_SYMBOL(syscalln_name_addr);

uintptr_t syscalln_addr(int nr, int is_compat)
{
    if (!is_compat && sys_call_table) return sys_call_table[nr];
    if (is_compat && compat_sys_call_table) return compat_sys_call_table[nr];
    return syscalln_name_addr(nr, is_compat);
}
KP_EXPORT_SYMBOL(syscalln_addr);

long raw_syscall0(long nr)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall0_f)addr)();
}
KP_EXPORT_SYMBOL(raw_syscall0);

long raw_syscall1(long nr, long arg0)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall1_f)addr)(arg0);
}
KP_EXPORT_SYMBOL(raw_syscall1);

long raw_syscall2(long nr, long arg0, long arg1)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall2_f)addr)(arg0, arg1);
}
KP_EXPORT_SYMBOL(raw_syscall2);

long raw_syscall3(long nr, long arg0, long arg1, long arg2)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall3_f)addr)(arg0, arg1, arg2);
}
KP_EXPORT_SYMBOL(raw_syscall3);

long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall4_f)addr)(arg0, arg1, arg2, arg3);
}
KP_EXPORT_SYMBOL(raw_syscall4);

long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall5_f)addr)(arg0, arg1, arg2, arg3, arg4);
}
KP_EXPORT_SYMBOL(raw_syscall5);

long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        regs.regs[5] = arg5;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall6_f)addr)(arg0, arg1, arg2, arg3, arg4, arg5);
}
KP_EXPORT_SYMBOL(raw_syscall6);

hook_err_t __fp_hook_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    if (!is_compat) {
        if (!sys_call_table) return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(sys_call_table + nr);
        if (has_syscall_wrapper) narg = 1;
        return fp_hook_wrap(fp_addr, narg, before, after, udata);
    } else {
        if (!compat_sys_call_table) return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(compat_sys_call_table + nr);
        if (has_syscall_wrapper) narg = 1;
        return fp_hook_wrap(fp_addr, narg, before, after, udata);
    }
}
KP_EXPORT_SYMBOL(__fp_hook_syscalln);

void __fp_unhook_syscalln(int nr, int is_compat, void *before, void *after)
{
    if (!is_compat) {
        if (!sys_call_table) return;
        uintptr_t fp_addr = (uintptr_t)(sys_call_table + nr);
        fp_hook_unwrap(fp_addr, before, after);
    } else {
        if (!compat_sys_call_table) return;
        uintptr_t fp_addr = (uintptr_t)(compat_sys_call_table + nr);
        fp_hook_unwrap(fp_addr, before, after);
    }
}
KP_EXPORT_SYMBOL(__fp_unhook_syscalln);

/*
sys_xxx.cfi_jt

hint #0x22  # bti c
b #0xfffffffffeb452f4
*/
hook_err_t __inline_hook_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    if (!addr) return -HOOK_BAD_ADDRESS;
    if (has_syscall_wrapper) narg = 1;
    return hook_wrap((void *)addr, narg, before, after, udata);
}
KP_EXPORT_SYMBOL(__inline_hook_syscalln);

void __inline_unhook_syscalln(int nr, int is_compat, void *before, void *after)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    hook_unwrap((void *)addr, before, after);
}
KP_EXPORT_SYMBOL(__inline_unhook_syscalln);

hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (sys_call_table) return __fp_hook_syscalln(nr, narg, 0, before, after, udata);
    return __inline_hook_syscalln(nr, narg, 0, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_syscalln);

void unhook_syscalln(int nr, void *before, void *after)
{
    if (sys_call_table) return __fp_unhook_syscalln(nr, 0, before, after);
    return __inline_unhook_syscalln(nr, 0, before, after);
}
KP_EXPORT_SYMBOL(unhook_syscalln);

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (compat_sys_call_table) return __fp_hook_syscalln(nr, narg, 1, before, after, udata);
    return __inline_hook_syscalln(nr, narg, 1, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_compat_syscalln);

void unhook_compat_syscalln(int nr, void *before, void *after)
{
    if (compat_sys_call_table) return __fp_unhook_syscalln(nr, 1, before, after);
    return __inline_unhook_syscalln(nr, 1, before, after);
}
KP_EXPORT_SYMBOL(unhook_compat_syscalln);

void syscall_init()
{
    for (int i = 0; i < sizeof(syscall_name_table) / sizeof(syscall_name_table[0]); i++) {
        uintptr_t *addr = (uintptr_t *)&syscall_name_table[i].name;
        *addr = link2runtime(*addr);
    }

    for (int i = 0; i < sizeof(compat_syscall_name_table) / sizeof(compat_syscall_name_table[0]); i++) {
        uintptr_t *addr = (uintptr_t *)&compat_syscall_name_table[i].name;
        *addr = link2runtime(*addr);
    }

    // sys_call_table = (typeof(sys_call_table))kallsyms_lookup_name("sys_call_table");
    // log_boot("sys_call_table addr: %llx\n", sys_call_table);

    // compat_sys_call_table = (typeof(compat_sys_call_table))kallsyms_lookup_name("compat_sys_call_table");
    // log_boot("compat_sys_call_table addr: %llx\n", compat_sys_call_table);

    has_config_compat = 0;
    has_syscall_wrapper = 0;

    if (kallsyms_lookup_name("__arm64_compat_sys_openat")) {
        has_config_compat = 1;
        has_syscall_wrapper = 1;
    } else {
        if (kallsyms_lookup_name("compat_sys_call_table") || kallsyms_lookup_name("compat_sys_openat")) {
            has_config_compat = 1;
        }
        if (kallsyms_lookup_name("__arm64_sys_openat")) {
            has_syscall_wrapper = 1;
        }
    }

    log_boot("syscall config_compat: %d\n", has_config_compat);
    log_boot("syscall has_wrapper: %d\n", has_syscall_wrapper);
}
