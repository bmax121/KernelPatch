/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
#include <hook.h>
#include <kallsyms.h>
#include <common.h>
#include <uapi/asm-generic/errno.h>

#include <predata.h>

struct pt_regs;

static inline bool should_cfi_pass(unsigned long target)
{
    return is_kp_text_area(target) || is_kp_hook_area(target) || is_kpm_rox_area(target);
}

enum bug_trap_type
{
    BUG_TRAP_TYPE_NONE = 0,
    BUG_TRAP_TYPE_WARN = 1,
    BUG_TRAP_TYPE_BUG = 2,
};

static enum bug_trap_type (*backup_report_cfi_failure)(struct pt_regs *regs, unsigned long addr, unsigned long *target,
                                                       u32 type) = 0;
static enum bug_trap_type replace_report_cfi_failure(struct pt_regs *regs, unsigned long addr, unsigned long *target,
                                                     u32 type)
{
    if (should_cfi_pass(*target)) {
        return BUG_TRAP_TYPE_WARN;
    }
    enum bug_trap_type rc = backup_report_cfi_failure(regs, addr, target, type);
    return rc;
}

typedef void (*cfi_check_fn)(uint64_t id, void *ptr, void *diag);

static void (*backup__cfi_slowpath)(uint64_t id, void *ptr, void *diag) = 0;
static void replace__cfi_slowpath(uint64_t id, void *ptr, void *diag)
{
    if (should_cfi_pass((unsigned long)ptr)) return;
    backup__cfi_slowpath(id, ptr, diag);
}

int bypass_kcfi()
{
    int rc = 0;

    // 6.1.0
    // todo: Is there more elegant way?
    unsigned long report_cfi_failure_addr = get_preset_patch_sym()->report_cfi_failure;
    if (report_cfi_failure_addr) {
        hook_err_t err = hook((void *)report_cfi_failure_addr, (void *)replace_report_cfi_failure,
                              (void **)&backup_report_cfi_failure);
        if (err) {
            log_boot("hook report_cfi_failure: %llx, error: %d\n", report_cfi_failure_addr, err);
            rc = err;
            goto out;
        }
    }

    // todo: direct modify cfi_shadow, __cfi_check?
    unsigned long __cfi_slowpath_addr = get_preset_patch_sym()->__cfi_slowpath_diag;
    if (!__cfi_slowpath_addr) {
        __cfi_slowpath_addr = get_preset_patch_sym()->__cfi_slowpath;
    }
    if (__cfi_slowpath_addr) {
        hook_err_t err =
            hook((void *)__cfi_slowpath_addr, (void *)replace__cfi_slowpath, (void **)&backup__cfi_slowpath);
        if (err) {
            log_boot("hook __cfi_slowpath_diag: %llx, error: %d\n", __cfi_slowpath_addr, err);
            rc = err;
            goto out;
        }
    }

    if (!report_cfi_failure_addr && !__cfi_slowpath_addr) {
        // not error
        log_boot("no symbol for pass kcfi\n");
    }

out:
    return rc;
}