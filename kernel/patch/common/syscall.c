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
    if (!upptr || IS_ERR(upptr)) return ERR_PTR((long)upptr);

    char __user *uptr;
    if (size == 8) {
        uptr = *upptr;
    } else {
        uptr = (char __user *)(unsigned long)*(int32_t *)upptr;
    }
    kvfree(upptr);
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

long raw_syscall0(long nr)
{
    uintptr_t addr = sys_call_table[nr];
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall0_f)addr)();
    return 0;
}

long raw_syscall1(long nr, long arg0)
{
    uintptr_t addr = sys_call_table[nr];
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall1_f)addr)(arg0);
}

long raw_syscall2(long nr, long arg0, long arg1)
{
    uintptr_t addr = sys_call_table[nr];
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall2_f)addr)(arg0, arg1);
}

long raw_syscall3(long nr, long arg0, long arg1, long arg2)
{
    uintptr_t addr = sys_call_table[nr];
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall3_f)addr)(arg0, arg1, arg2);
}

long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3)
{
    uintptr_t addr = sys_call_table[nr];
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall4_f)addr)(arg0, arg1, arg2, arg3);
}

long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4)
{
    uintptr_t addr = sys_call_table[nr];
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall5_f)addr)(arg0, arg1, arg2, arg3, arg4);
}

long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    uintptr_t addr = sys_call_table[nr];
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
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

static uint64_t search_sys_call_table_addr()
{
    uint64_t addr = kernel_va;
    uint64_t _etext = kallsyms_lookup_name("_etext");
    addr = addr > _etext ? addr : _etext;

    char *prefix[2];
    prefix[0] = "__arm64_";
    prefix[1] = "";

    char *io_setup = "sys_io_setup";
    char *io_destory = "sys_io_destroy";

    char *suffix[3];
    suffix[0] = ".cfi_jt";
    suffix[1] = ".cfi";
    suffix[2] = "";

    char buf[128];

    uint64_t sc0_addr = 0;
    uint64_t sc1_addr = 0;

    int i = 0, k = 0;

    for (; k < 3; k++) {
        i = 0;
        for (; i < 2; i++) {
            buf[0] = '\0';
            strcat(buf, prefix[i]);
            strcat(buf, io_setup);
            strcat(buf, suffix[k]);
            sc0_addr = kallsyms_lookup_name(buf);
            if (!sc0_addr) continue;

            buf[0] = '\0';
            strcat(buf, prefix[i]);
            strcat(buf, io_destory);
            strcat(buf, suffix[k]);
            sc1_addr = kallsyms_lookup_name(buf);
            if (!sc1_addr) return 0;
        }
    }

    for (; addr < kernel_va + kernel_size; addr += 8) {
        uint64_t val0 = *(uint64_t *)addr;
        if (val0 != sc0_addr) continue;
        uint64_t val1 = *(uint64_t *)(addr + 8);
        if (val1 == sc1_addr) return addr;
    }
    return 0;
}

int syscall_init()
{
    int rc = 0;
    sys_call_table = (typeof(sys_call_table))kallsyms_lookup_name("sys_call_table");
    if (unlikely(!sys_call_table)) {
        sys_call_table = (typeof(sys_call_table))search_sys_call_table_addr();
    }
    if (unlikely(!sys_call_table)) {
        rc = -ENOENT;
        log_boot("no symbol sys_call_table\n");
        goto out;
    }
    log_boot("sys_call_table addr: %llx\n", sys_call_table);

    compat_sys_call_table = (typeof(compat_sys_call_table))kallsyms_lookup_name("compat_sys_call_table");
    log_boot("compat_sys_call_table addr: %llx\n", compat_sys_call_table);

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

out:
    return rc;
}
