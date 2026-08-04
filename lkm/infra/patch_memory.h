/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Patch read-only kernel memory (used to overwrite a sys_call_table entry).
 * Ported from KernelSU's hook/patch_memory.c (arm64). init_mm is resolved at
 * init rather than referenced directly, so the ko never depends on init_mm
 * being exported.
 */
#ifndef _KP_LKM_PATCH_MEMORY_H_
#define _KP_LKM_PATCH_MEMORY_H_
#include <linux/types.h>

/* Only arm64 is wired up in the framework. */
#ifndef __aarch64__
#error "kp lkm framework: only arm64 is wired up for now"
#endif

#define KP_PATCH_TEXT_FLUSH_DCACHE 1
#define KP_PATCH_TEXT_FLUSH_ICACHE 2

int kp_patch_memory_init(void); /* resolve aarch64_insn_patch_text_nosync */
int kp_patch_text(void *dst, const void *src, size_t len, int flags);

#endif /* _KP_LKM_PATCH_MEMORY_H_ */
