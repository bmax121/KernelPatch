#ifndef __ASM_PTRACE_H
#define __ASM_PTRACE_H

#include <init/ksyms.h>
#include <pgtable.h>
#include <stdbool.h>
#include <uapi/asm-generic/unistd.h>

struct user_pt_regs
{
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

struct pt_regs
{
    union
    {
        struct user_pt_regs user_regs;
        struct
        {
            u64 regs[31];
            u64 sp;
            u64 pc;
            u64 pstate;
        };
    };
    u64 orig_x0;
#ifdef __AARCH64EB__
    u32 unused2;
    s32 syscallno;
#else
    s32 syscallno;
    u32 unused2;
#endif
    u64 sdei_ttbr1;
    /* Only valid when ARM64_HAS_GIC_PRIO_MASKING is enabled. */
    u64 pmr_save;
    u64 stackframe[2];

    /* Only valid for some EL1 exceptions. */
    u64 lockdep_hardirqs;
    u64 exit_rcu;
};

#endif