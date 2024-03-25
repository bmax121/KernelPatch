/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <taskext.h>
#include <asm/current.h>
#include <hook.h>
#include <syscall.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/string.h>

KPM_NAME("make-shamiko-happy");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("Tell Shamiko(0.7.4) that we're KernelSU, make it happy.");

void prctl_before(hook_fargs6_t *args, void *udata)
{
    uint64_t option = syscall_argn(args, 0);
    if (option != 0xDEADBEEF) return;

    struct task_struct *task = current;

    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t *)((uintptr_t)cred + cred_offset.euid_offset);

    if (uid) return;

    uint64_t cmd = syscall_argn(args, 1);
    uint64_t arg2 = syscall_argn(args, 2);
    uint64_t arg3 = syscall_argn(args, 3);
    uint64_t arg4 = syscall_argn(args, 4);
    uint64_t arg5 = syscall_argn(args, 5);

    uint32_t reply_ok = 0xDEADBEEF;

    pr_info("ksu prctl: %x, %x, %x, %x, %x, %x\n", option, cmd, arg2, arg3, arg4, arg5);

    if (cmd == 2) {
        uint32_t version = 11682;
        int rc = compat_copy_to_user((void *)arg2, &version, 4);
        printk("fake ksu version: %d, %d", version, rc);
    } else if (cmd == 12 || cmd == 13) {
        bool res;
        if (cmd == 13) {
            res = true;
            printk("fake ksu unmount: uid: %d\n", arg2);
        } else {
            res = false;
            printk("fake ksu allow: uid: %d\n", arg2);
        }
        compat_copy_to_user((void *)arg3, &res, sizeof(res));
        compat_copy_to_user((void *)arg4, &reply_ok, sizeof(reply_ok));
    } else {
    }

    args->ret = 0;
    args->skip_origin = true;
}

static long do_init(const char *args, const char *event, void *__user reserved)
{
    int rc = fp_hook_syscalln(__NR_prctl, 6, prctl_before, 0, 0);
    pr_info("init rc: %d\n", rc);
    return 0;
}

static long do_control0(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

static long do_control1(void *a1, void *a2, void *a3)
{
    return 0;
}

static long do_exit(void *__user reserved)
{
    fp_unhook_syscall(__NR_prctl, prctl_before, 0);
    return 0;
}

KPM_INIT(do_init);
KPM_CTL0(do_control0);
KPM_CTL1(do_control1);
KPM_EXIT(do_exit);
