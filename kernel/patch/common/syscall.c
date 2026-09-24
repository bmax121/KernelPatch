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
#include <kallsyms.h>
#include <kp_spinlock.h>
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

hook_err_t fp_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
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
KP_EXPORT_SYMBOL(fp_wrap_syscalln);

void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
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
KP_EXPORT_SYMBOL(fp_unwrap_syscalln);

/*
sys_xxx.cfi_jt

hint #0x22  # bti c
b #0xfffffffffeb452f4
*/
hook_err_t inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    if (!addr) return -HOOK_BAD_ADDRESS;
    if (has_syscall_wrapper) narg = 1;
    return hook_wrap((void *)addr, narg, before, after, udata);
}
KP_EXPORT_SYMBOL(inline_wrap_syscalln);

void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    hook_unwrap((void *)addr, before, after);
}
KP_EXPORT_SYMBOL(inline_unwrap_syscalln);

/*
 * Global syscall dispatcher.
 *
 * A single inline hook on el0_svc_common covers every syscall, native and
 * compat32 alike, with one uniform trampoline. Per-syscall registrations are
 * kept in a small static table and fanned out from that one hook, so the
 * sys_call_table entries are never patched and every syscall pays the same
 * overhead (no per-syscall timing fingerprint).
 *
 * The registered callbacks run against the hook_fargs8_t captured by the inline
 * hook's transit, whose arg0 is the pt_regs pointer; syscall_args() therefore
 * reads regs->regs[] exactly as it did under the per-syscall hook, and
 * syscall_argn_p() still writes straight into the live register frame.
 *
 * skip_origin (only used by the magic supercall) is honoured only when the hook
 * target is invoke_syscall, i.e. at handler granularity: there it suppresses the
 * real syscall while el0_svc_common still runs syscall_trace_enter/exit around it.
 * If only el0_svc_common could be resolved, skip_origin is refused (it would skip
 * that whole function) and such callers fall back to hook_syscalln_legacy().
 */
#define SYSCALL_HOOK_SLOT_NUM 64
/* More than this many callbacks on one syscall number would be unusual; the
 * excess is skipped rather than overflowing the dispatch stack frame. */
#define SYSCALL_HOOK_MAX_MATCH 16

typedef void (*syscall_hook_cb_t)(void *fargs, void *udata);
typedef int (*syscall_hook_gate_t)(void);

typedef struct
{
    int32_t nr;
    int32_t is_compat;
    void *before;
    void *after;
    void *udata;
    int8_t allow_skip;
    int8_t bypass_gate;
    volatile int8_t state;
} syscall_hook_slot_t;

static syscall_hook_slot_t syscall_hooks[SYSCALL_HOOK_SLOT_NUM];
/* High-water mark of used slots; lets the hot path bail out immediately when
 * nothing is registered. */
static volatile int syscall_hook_high = 0;
static volatile int syscall_hook_global = 0;
/* 1 when hooked at invoke_syscall (handler granularity), 0 when hooked at
 * el0_svc_common's entry. Only the former can honour skip_origin. */
static volatile int syscall_hook_handler_granular = 0;
/* Optional uid gate, evaluated once per syscall for all callbacks. */
static syscall_hook_gate_t syscall_hook_gate = 0;
static spinlock_t syscall_hook_lock;

struct syscall_hook_snapshot
{
    syscall_hook_cb_t before;
    syscall_hook_cb_t after;
    void *udata;
    int8_t allow_skip;
};

static void syscall_hook_barrier(void)
{
    asm volatile("dsb ish" ::: "memory");
}

static int syscall_hook_collect(int nr, int is_compat, int gate_ok, struct syscall_hook_snapshot *out, int max)
{
    int n = 0;
    int high = syscall_hook_high;
    if (high > SYSCALL_HOOK_SLOT_NUM) high = SYSCALL_HOOK_SLOT_NUM;

    for (int i = 0; i < high; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_READY) continue;
        if (syscall_hooks[i].nr != nr || syscall_hooks[i].is_compat != is_compat) continue;
        if (!gate_ok && !syscall_hooks[i].bypass_gate) continue;
        if (n >= max) break;
        out[n].before = (syscall_hook_cb_t)syscall_hooks[i].before;
        out[n].after = (syscall_hook_cb_t)syscall_hooks[i].after;
        out[n].udata = syscall_hooks[i].udata;
        out[n].allow_skip = syscall_hooks[i].allow_skip;
        n++;
    }
    return n;
}

static hook_err_t syscall_hook_add(int nr, int is_compat, void *before, void *after, void *udata, int allow_skip,
                                   int bypass_gate)
{
    unsigned long flags = kp_private_spin_lock(&syscall_hook_lock);

    for (int i = 0; i < SYSCALL_HOOK_SLOT_NUM; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_READY) continue;
        if (syscall_hooks[i].nr != nr || syscall_hooks[i].is_compat != is_compat) continue;
        if ((before && syscall_hooks[i].before == before) || (after && syscall_hooks[i].after == after)) {
            kp_private_spin_unlock(&syscall_hook_lock, flags);
            return -HOOK_DUPLICATED;
        }
    }

    for (int i = 0; i < SYSCALL_HOOK_SLOT_NUM; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_EMPTY) continue;
        syscall_hooks[i].state = CHAIN_ITEM_STATE_BUSY;
        syscall_hook_barrier();
        syscall_hooks[i].nr = nr;
        syscall_hooks[i].is_compat = is_compat;
        syscall_hooks[i].udata = udata;
        syscall_hooks[i].before = before;
        syscall_hooks[i].after = after;
        syscall_hooks[i].allow_skip = allow_skip;
        syscall_hooks[i].bypass_gate = bypass_gate;
        syscall_hook_barrier();
        syscall_hooks[i].state = CHAIN_ITEM_STATE_READY;
        if (i + 1 > syscall_hook_high) syscall_hook_high = i + 1;
        kp_private_spin_unlock(&syscall_hook_lock, flags);
        logkv("syscall hook add: nr %d compat %d, %llx, %llx\n", nr, is_compat, before, after);
        return HOOK_NO_ERR;
    }

    kp_private_spin_unlock(&syscall_hook_lock, flags);
    logkv("syscall hook add: nr %d compat %d failed\n", nr, is_compat);
    return -HOOK_CHAIN_FULL;
}

static void syscall_hook_remove(int nr, int is_compat, void *before, void *after)
{
    unsigned long flags = kp_private_spin_lock(&syscall_hook_lock);

    for (int i = 0; i < SYSCALL_HOOK_SLOT_NUM; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_READY) continue;
        if (syscall_hooks[i].nr != nr || syscall_hooks[i].is_compat != is_compat) continue;
        int match = 0;
        if (before && syscall_hooks[i].before == before) match = 1;
        if (after && syscall_hooks[i].after == after) match = 1;
        if (!match) continue;
        syscall_hooks[i].state = CHAIN_ITEM_STATE_BUSY;
        syscall_hook_barrier();
        syscall_hooks[i].udata = 0;
        syscall_hooks[i].before = 0;
        syscall_hooks[i].after = 0;
        syscall_hooks[i].allow_skip = 0;
        syscall_hooks[i].bypass_gate = 0;
        syscall_hook_barrier();
        syscall_hooks[i].state = CHAIN_ITEM_STATE_EMPTY;
        break;
    }

    kp_private_spin_unlock(&syscall_hook_lock, flags);
}

int syscall_hook_global_enabled(void)
{
    return syscall_hook_global;
}
KP_EXPORT_SYMBOL(syscall_hook_global_enabled);

/* Register the single uid gate evaluated once per syscall before dispatching any
 * callback. Passing NULL disables gating (all callbacks run). */
void syscall_hook_set_gate(int (*gate)(void))
{
    syscall_hook_gate = gate;
}
KP_EXPORT_SYMBOL(syscall_hook_set_gate);

/* scno is arg1 of el0_svc_common; on the odd kernel where that argument is
 * absent, fall back to the userspace syscall-number register (x8 native, r7
 * compat32), which is what the entry stubs load scno from. */
static long syscall_dispatch_nr(struct pt_regs *regs, unsigned long scno, int is_compat)
{
    long nr = (long)scno;
    if (nr < 0 || nr >= 1024) nr = (long)(is_compat ? regs->regs[7] : regs->regs[8]);
    return nr;
}

/* Sized as hook_fargs8_t (the largest callback type used in-tree) even though
 * el0_svc_common takes four arguments: has_syscall_wrapper makes syscall_argn()
 * read the register frame rather than the struct's args[], but keeping the
 * buffer large enough means a callback that does read args->arg4..7 directly
 * stays in bounds. */
static void syscall_dispatch_before(hook_fargs8_t *args, void *udata)
{
    (void)udata;
    struct pt_regs *regs = (struct pt_regs *)args->arg0;
    if (!regs) return;

    int is_compat = compat_user_mode(regs) ? 1 : 0;
    long nr = syscall_dispatch_nr(regs, args->arg1, is_compat);

    if (!syscall_hook_high) return;

    /* One uid gate, evaluated once per syscall for every callback, instead of a
     * root check inside each callback. For a process that is not su-authorized
     * nothing is dispatched, so behavior and cost are the same across all
     * syscalls: no per-syscall fingerprint, and fstatat/statx/... cannot
     * disagree. Slots registered with bypass_gate (the magic supercall, which
     * authenticates with its own key) still run. */
    int gate_ok = 1;
    if (syscall_hook_gate) gate_ok = syscall_hook_gate() ? 1 : 0;

    struct syscall_hook_snapshot snap[SYSCALL_HOOK_MAX_MATCH];
    int n = syscall_hook_collect((int)nr, is_compat, gate_ok, snap, SYSCALL_HOOK_MAX_MATCH);
    if (!n) return;

    /* Hooked at invoke_syscall (handler granularity) el0_svc_common has already
     * set these; hooked at its entry we must set them ourselves so callbacks
     * that inspect them (resolve_pt_regs scans the stack for a matching frame)
     * see the same state as under the per-syscall hook. */
    if (!syscall_hook_handler_granular) {
        regs->orig_x0 = regs->regs[0];
        regs->syscallno = nr;
    }

    /* arg1..arg3 are scno/sc_nr/table, not syscall arguments; they must reach the
     * origin unchanged for it to pick the right handler. */
    uint64_t keep_arg1 = args->arg1;
    uint64_t keep_arg2 = args->arg2;
    uint64_t keep_arg3 = args->arg3;

    args->skip_origin = 0;
    args->ret = 0;

    int can_skip = 0;
    for (int i = 0; i < n; i++) {
        if (snap[i].allow_skip) can_skip = 1;
        if (snap[i].before) snap[i].before(args, snap[i].udata);
    }

    args->arg1 = keep_arg1;
    args->arg2 = keep_arg2;
    args->arg3 = keep_arg3;

    /* Honour skip_origin only where it means "skip this one syscall's handler".
     * At invoke_syscall granularity el0_svc_common still runs syscall_trace_enter
     * and syscall_trace_exit around it, so the overridden result has to be placed
     * in regs->regs[0] here. When hooked at el0_svc_common's entry, skip_origin
     * would skip that whole function (tracing, exit work and all), so it is
     * refused unless the caller explicitly opted in. */
    if (args->skip_origin && can_skip && syscall_hook_handler_granular) {
        regs->regs[0] = args->ret;
    } else {
        args->skip_origin = 0;
    }
}

static void syscall_dispatch_after(hook_fargs8_t *args, void *udata)
{
    (void)udata;
    struct pt_regs *regs = (struct pt_regs *)args->arg0;
    if (!regs) return;

    int is_compat = compat_user_mode(regs) ? 1 : 0;
    /* Use the scno captured by the transit at function entry, not regs->syscallno:
     * el0_svc_common only assigns syscallno for in-range syscalls, so an invalid
     * number would leave the previous syscall's value there and we would run the
     * wrong afters. args->arg1 is the original scno; callbacks that rewrite a
     * syscall argument go through set_syscall_argn(), which touches regs->regs[],
     * not this copy. */
    long nr = syscall_dispatch_nr(regs, args->arg1, is_compat);

    if (!syscall_hook_high) return;

    /* Same gate as the before phase: an after callback must never run without
     * its before callback having run. */
    int gate_ok = 1;
    if (syscall_hook_gate) gate_ok = syscall_hook_gate() ? 1 : 0;

    struct syscall_hook_snapshot snap[SYSCALL_HOOK_MAX_MATCH];
    int n = syscall_hook_collect((int)nr, is_compat, gate_ok, snap, SYSCALL_HOOK_MAX_MATCH);
    if (!n) return;

    /* The real return value lives in regs->regs[0]; el0_svc_common returns void,
     * so mirror it into fargs->ret for the after callbacks and copy any change
     * back, matching the fp-hook chain semantics. */
    args->ret = regs->regs[0];
    for (int i = n - 1; i >= 0; i--) {
        if (snap[i].after) snap[i].after(args, snap[i].udata);
    }
    regs->regs[0] = args->ret;
}

void syscall_dispatch_init(void)
{
    if (syscall_hook_global) return;
    if (!has_syscall_wrapper) {
        log_boot("syscall dispatcher: no syscall wrapper, keep per-syscall hooks\n");
        return;
    }

    /* Prefer invoke_syscall: it runs after syscall_trace_enter (seccomp/ptrace)
     * and before syscall_trace_exit, i.e. at the same granularity as the old
     * per-syscall hooks. Hooking there lets skip_origin skip only the real
     * handler while el0_svc_common still performs its entry/exit work. Fall back
     * to el0_svc_common, which is coarser and cannot honour skip_origin.
     * GCC clones (LTO/constprop/isra) get a trailing '.' suffix; the helper
     * requires that separator, so el0_svc_common_compat is not matched. */
    uintptr_t addr = 0;
    const char *name = 0;
    int granular = 0;

    addr = kallsyms_lookup_name("invoke_syscall");
    if (addr) {
        name = "invoke_syscall";
        granular = 1;
    }

    if (!addr) {
        addr = kallsyms_lookup_name("el0_svc_common");
        if (addr) name = "el0_svc_common";
    }
    
    if (!addr) {
        log_boot("syscall dispatcher: no invoke_syscall/el0_svc_common, keep per-syscall hooks\n");
        return;
    }

    hook_err_t err = hook_wrap8((void *)addr, syscall_dispatch_before, syscall_dispatch_after, 0);
    if (err) {
        log_boot("syscall dispatcher: hook %s error %d, keep per-syscall hooks\n", name, err);
        return;
    }

    syscall_hook_handler_granular = granular;
    syscall_hook_barrier();
    syscall_hook_global = 1;
    log_boot("syscall dispatcher: hooked %s at %llx (skip_origin %s), global syscall hook enabled\n", name,
             (uint64_t)addr, granular ? "supported" : "unsupported");
}
KP_EXPORT_SYMBOL(syscall_dispatch_init);

hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (syscall_hook_global) return syscall_hook_add(nr, 0, before, after, udata, 0, 0);
    if (sys_call_table) return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_syscalln);

void unhook_syscalln(int nr, void *before, void *after)
{
    if (syscall_hook_global) return syscall_hook_remove(nr, 0, before, after);
    if (sys_call_table) return fp_unwrap_syscalln(nr, 0, before, after);
    return inline_unwrap_syscalln(nr, 0, before, after);
}
KP_EXPORT_SYMBOL(unhook_syscalln);

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (syscall_hook_global) return syscall_hook_add(nr, 1, before, after, udata, 0, 0);
    if (compat_sys_call_table) return fp_wrap_syscalln(nr, narg, 1, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 1, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_compat_syscalln);

/* Like hook_syscalln but the callback may set skip_origin to suppress the real
 * syscall. Honoured only when the dispatcher is hooked at invoke_syscall; if it
 * is hooked at el0_svc_common (or not at all) this falls back to the per-syscall
 * mechanism, which implements skip_origin at handler granularity. */
hook_err_t hook_syscalln_override(int nr, int narg, void *before, void *after, void *udata)
{
    /* bypass_gate: the magic supercall authenticates with its own key, so it must
     * still be dispatched for a uid that is not on the su allow list. */
    if (syscall_hook_global && syscall_hook_handler_granular)
        return syscall_hook_add(nr, 0, before, after, udata, 1, 1);
    if (sys_call_table) return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_syscalln_override);

void unhook_compat_syscalln(int nr, void *before, void *after)
{
    if (syscall_hook_global) return syscall_hook_remove(nr, 1, before, after);
    if (compat_sys_call_table) return fp_unwrap_syscalln(nr, 1, before, after);
    return inline_unwrap_syscalln(nr, 1, before, after);
}
KP_EXPORT_SYMBOL(unhook_compat_syscalln);

/* Original per-syscall mechanism, kept for callbacks that need skip_origin
 * (the magic supercall) and as the fallback when el0_svc_common is unavailable. */
hook_err_t hook_syscalln_legacy(int nr, int narg, void *before, void *after, void *udata)
{
    if (sys_call_table) return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_syscalln_legacy);

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

    sys_call_table = (typeof(sys_call_table))kallsyms_lookup_name("sys_call_table");
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
}
