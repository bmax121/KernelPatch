#include "syscall.h"

#include <cache.h>
#include <ktypes.h>
#include <hook.h>
#include <common.h>
#include <linux/string.h>
#include <symbol.h>
#include <uapi/asm-generic/errno.h>

uintptr_t kvar_def(sys_call_table) = 0;
KP_EXPORT_SYMBOL(kvar(sys_call_table));

uintptr_t kvar_def(compat_sys_call_table) = 0;
KP_EXPORT_SYMBOL(kvar(compat_sys_call_table));

bool syscall_has_wrapper = false;
KP_EXPORT_SYMBOL(syscall_has_wrapper);

bool has_config_compat = false;
KP_EXPORT_SYMBOL(has_config_compat);

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
    uintptr_t addr = kvar(sys_call_table)[nr];
    if (syscall_has_wrapper) {
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall0_f)addr)();
    return 0;
}

long raw_syscall1(long nr, long arg0)
{
    uintptr_t addr = kvar(sys_call_table)[nr];
    if (syscall_has_wrapper) {
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall1_f)addr)(arg0);
}

long raw_syscall2(long nr, long arg0, long arg1)
{
    uintptr_t addr = kvar(sys_call_table)[nr];
    if (syscall_has_wrapper) {
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
    uintptr_t addr = kvar(sys_call_table)[nr];
    if (syscall_has_wrapper) {
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
    uintptr_t addr = kvar(sys_call_table)[nr];
    if (syscall_has_wrapper) {
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
    uintptr_t addr = kvar(sys_call_table)[nr];
    if (syscall_has_wrapper) {
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
    uintptr_t addr = kvar(sys_call_table)[nr];
    if (syscall_has_wrapper) {
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

int syscall_init()
{
    int rc = 0;
    kvar(sys_call_table) = (typeof(kvar(sys_call_table)))kallsyms_lookup_name("sys_call_table");
    if (!kvar(sys_call_table)) {
        rc = -ENOENT;
        log_boot("no symbol sys_call_table\n");
        goto out;
    }
    kvar(compat_sys_call_table) = (typeof(kvar(compat_sys_call_table)))kallsyms_lookup_name("compat_sys_call_table");

    has_config_compat = !!kvar(compat_sys_call_table);
    log_boot("syscall config_compat: %d\n", has_config_compat);

    syscall_has_wrapper = !!kallsyms_lookup_name("__arm64_sys_openat");
    log_boot("syscall has_wrapper: %d\n", syscall_has_wrapper);

out:
    return rc;
}
