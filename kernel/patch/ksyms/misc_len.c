/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_MISC_LEN_H_
#define _KP_MISC_LEN_H_

#include <ktypes.h>
#include <ksyms.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/sched/task.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include <linux/init_task.h>

struct task_struct *kvar(init_task) = 0;
union thread_union *kvar(init_thread_union) = 0;
struct cred *kvar(init_cred) = 0;
struct group_info *kvar(init_groups) = 0;

int kvlen(init_task) = -1;
int kvlen(init_cred) = -1;
int kvlen(init_thread_union) = -1;

int linux_sybmol_len_init()
{
    int rc = 0;

    kvar_lookup_name(init_task);
    kvar_lookup_name(init_thread_union);
    kvar_lookup_name(init_cred);
    kvar_lookup_name(init_groups);

    if (!kvar(init_task) || !kvar(init_thread_union) || !kvar(init_cred) || !kvar(init_groups)) {
        rc = -ENOENT;
        log_boot("no symbol init_task or init_thread_union or init_cred or init_groups\n");
        goto out;
    }

    unsigned long offset = 0;
    unsigned long size = 0;
    char mod[16] = { '\0' };
    char name[16] = { '\0' };

    log_boot("struct size: \n");

    if (!lookup_symbol_attrs) {
        log_boot("    use default\n");
        kvlen(init_cred) = 0x100;
        kvlen(init_task) = 0x1400;
        kvlen(init_thread_union) = 0x4000;
    } else {
        lookup_symbol_attrs((unsigned long)kvar(init_cred), &size, &offset, mod, name);
        kvlen(init_cred) = size;
        lookup_symbol_attrs((unsigned long)kvar(init_task), &size, &offset, mod, name);
        kvlen(init_task) = size;
        lookup_symbol_attrs((unsigned long)kvar(init_thread_union), &size, &offset, mod, name);
        kvlen(init_thread_union) = size;
    }
    thread_size = kvlen(init_thread_union);

    log_boot("    init_cred: %x\n", kvlen(init_cred));
    log_boot("    init_task: %x\n", kvlen(init_task));
    log_boot("    thread_union: %x\n", kvlen(init_thread_union));
out:
    return rc;
}

#endif