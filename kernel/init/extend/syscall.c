#include "syscall.h"

#include <cache.h>
#include <ktypes.h>
#include <hook.h>
#include <common.h>
#include <linux/string.h>

bool syscall_has_wrapper = false;
uintptr_t syscall_table_addr = 0;
uintptr_t compat_syscall_table_addr = 0;

void inline_syscall_with(long nr, uintptr_t *old, uintptr_t new)
{
    uintptr_t addr = syscall_table_addr + nr * sizeof(uintptr_t);
    uint64_t func = *(uintptr_t *)addr;
    hook((void *)func, (void *)new, (void **)old);
}

void inline_compat_syscall_with(long nr, uintptr_t *old, uintptr_t new)
{
    uintptr_t addr = compat_syscall_table_addr + nr * sizeof(uintptr_t);
    uint64_t func = *(uintptr_t *)addr;
    hook((void *)func, (void *)new, (void **)old);
}

// todo: Control Flow Integrity, CONFIG_LTO_CLANG=y CONFIG_CFI_CLANG=y
void replace_syscall_with(long nr, uintptr_t *old, uintptr_t new)
{
    uintptr_t addr = syscall_table_addr + nr * sizeof(uintptr_t);
    *old = *(uintptr_t *)addr;
    uintptr_t *pte = get_pte(addr);
    uintptr_t ori_prot = *pte;
    *pte = (ori_prot | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_kernel_page(addr);
    *(uintptr_t *)addr = new;
    // flush_icache_all();
    *pte = ori_prot;
    flush_tlb_kernel_page(addr);
}

void replace_compat_syscall_whit(long nr, uintptr_t *old, uintptr_t new)
{
    uintptr_t addr = compat_syscall_table_addr + nr * sizeof(uintptr_t);
    *old = *(uintptr_t *)addr;
    uintptr_t *pte = get_pte(addr);
    uintptr_t ori_prot = *pte;
    *pte = (ori_prot | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_kernel_page(addr);
    *(uintptr_t *)addr = new;
    // flush_icache_all();
    *pte = ori_prot;
    flush_tlb_kernel_page(addr);
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
    uintptr_t addr = syscall_table_addr + nr * sizeof(uintptr_t);
    addr = *(uintptr_t *)addr;
    if (syscall_has_wrapper) {
        // todo:
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall0_f)addr)();
    return 0;
}

long raw_syscall1(long nr, long arg0)
{
    uintptr_t addr = syscall_table_addr + nr * sizeof(uintptr_t);
    addr = *(uintptr_t *)addr;
    if (syscall_has_wrapper) {
        struct pt_regs regs;
        memset(&regs, 0, sizeof(regs));
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall1_f)addr)(arg0);
}

long raw_syscall2(long nr, long arg0, long arg1)
{
    uintptr_t addr = syscall_table_addr + nr * sizeof(uintptr_t);
    addr = *(uintptr_t *)addr;
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
    uintptr_t addr = syscall_table_addr + nr * sizeof(uintptr_t);
    addr = *(uintptr_t *)addr;
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
    uintptr_t addr = syscall_table_addr + nr * sizeof(uintptr_t);
    addr = *(uintptr_t *)addr;
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
    uintptr_t addr = syscall_table_addr + nr * sizeof(uintptr_t);
    addr = *(uintptr_t *)addr;
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
    uintptr_t addr = syscall_table_addr + nr * sizeof(uintptr_t);
    addr = *(uintptr_t *)addr;
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
    compat_syscall_table_addr = kallsyms_lookup_name("compat_sys_call_table");
    syscall_table_addr = kallsyms_lookup_name("sys_call_table");
    syscall_has_wrapper = kallsyms_lookup_name("__arm64_sys_openat") ? true : false;
    logkd("syscall has wrapper: %d\n", syscall_has_wrapper);
    return 0;
}
