/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * supercall_trampoline.S - ARM64 assembly trampoline for syscall 45 anti-sidechannel
 *
 * Scheme G3: Magic cookie check (bit[16:31] of ver_and_cmd == 0x1158)
 * - If magic matches → slow path (C function, full auth + dispatch)
 * - If magic doesn't match → fast path (tail-call to original, zero overhead)
 *
 * Hunter/FingerprintCheck test probes: syscall(45, key, 0x1000)
 *   → bit[16:31] = 0x0000 ≠ 0x1158 → fast path → timing indistinguishable from unhoooked
 *
 * Real APatch supercall: syscall(45, key, ver_and_cmd(key, cmd))
 *   → ver_and_cmd() sets bit[16:31] = 0x1158 → slow path → full auth + dispatch
 *
 * CRITICAL: Variables g_orig_wrapper/nowrap/compat must be non-static in supercall.c
 *   so that adrp can find them via PC-relative addressing (auto-relocated at load time).
 *   Do NOT use a storage indirection variable (kpimg globals are compile-time offsets,
 *   NOT runtime addresses — double-indirection via a storage pointer causes kernel panic).
 *
 * Two modes (selected at install time by supercall_install() based on has_syscall_wrapper):
 *   wrapper mode (has_syscall_wrapper=1): sys_truncate(struct pt_regs *regs)
 *     → regs in x0, ver_and_cmd in regs->regs[1] (offset 8 from regs)
 *   nowrap  mode (has_syscall_wrapper=0): sys_truncate(long arg0, long arg1, ...)
 *     → arg0 in x0, ver_and_cmd (arg1) in x1
 *
 * Anti-sidechannel v4-G (ckb-custom branch)
 * Date: 2026-04-18
 */

    .text
    .align  2

/*
 * supercall_trampoline_wrapper - for has_syscall_wrapper=1 kernels
 *
 * Called as: sys_truncate(struct pt_regs *regs)
 *   x0 = regs (pt_regs pointer)
 *   regs->regs[1] = ver_and_cmd (second syscall arg, at offset 8 from regs)
 *
 * Magic check: bit[16:31] of ver_and_cmd == 0x1158
 */
    .global supercall_trampoline_wrapper
    .type   supercall_trampoline_wrapper, %function
supercall_trampoline_wrapper:
    ldr     x9, [x0, #8]               /* regs->regs[1] = ver_and_cmd */
    lsr     x10, x9, #16
    and     x10, x10, #0xFFFF
    mov     x11, #0x1158
    cmp     x10, x11
    b.eq    .Lslow_wrapper

    /* Fast path: not a real supercall, tail-call to original (zero overhead) */
    adrp    x9, g_orig_wrapper
    ldr     x9, [x9, :lo12:g_orig_wrapper]
    br      x9

.Lslow_wrapper:
    /* Slow path: magic matches, go through C auth + dispatch */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    bl      supercall_g_slow_path_wrapper
    ldp     x29, x30, [sp], #16
    ret
    .size   supercall_trampoline_wrapper, .-supercall_trampoline_wrapper

/*
 * supercall_trampoline_nowrap - for has_syscall_wrapper=0 kernels
 *
 * Called as: sys_truncate(long arg0, long arg1, long arg2, ...)
 *   x0 = arg0 (key string pointer)
 *   x1 = arg1 = ver_and_cmd
 *
 * Magic check: bit[16:31] of x1 == 0x1158
 */
    .global supercall_trampoline_nowrap
    .type   supercall_trampoline_nowrap, %function
supercall_trampoline_nowrap:
    lsr     x10, x1, #16               /* ver_and_cmd in x1 */
    and     x10, x10, #0xFFFF
    mov     x11, #0x1158
    cmp     x10, x11
    b.eq    .Lslow_nowrap

    /* Fast path: tail-call to original */
    adrp    x9, g_orig_nowrap
    ldr     x9, [x9, :lo12:g_orig_nowrap]
    br      x9

.Lslow_nowrap:
    /* Slow path */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    bl      supercall_g_slow_path_nowrap
    ldp     x29, x30, [sp], #16
    ret
    .size   supercall_trampoline_nowrap, .-supercall_trampoline_nowrap

/*
 * supercall_trampoline_compat - for 32-bit compat syscalls
 *
 * 32-bit apps cannot issue valid APatch supercalls (APatch requires 64-bit key handling).
 * This trampoline is a pure passthrough to the original truncate compat handler,
 * providing zero overhead on the fast path.
 */
    .global supercall_trampoline_compat
    .type   supercall_trampoline_compat, %function
supercall_trampoline_compat:
    adrp    x9, g_orig_compat
    ldr     x9, [x9, :lo12:g_orig_compat]
    br      x9
    .size   supercall_trampoline_compat, .-supercall_trampoline_compat
