/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <common.h>
#include <kputils.h>
#include <ktypes.h>
#include <hook.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>

#include "fstat.h"

KPM_NAME(FSTAT_MOD_NAME);
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("Modify the state of file system");

typedef __s64 time64_t;
typedef __u64 timeu64_t;

struct timespec64
{
    time64_t tv_sec; /* seconds */
    long tv_nsec; /* nanoseconds */
};

struct stat
{
    unsigned long st_dev; /* Device.  */
    unsigned long st_ino; /* File serial number.  */
    unsigned int st_mode; /* File mode.  */
    unsigned int st_nlink; /* Link count.  */
    unsigned int st_uid; /* User ID of the file's owner.  */
    unsigned int st_gid; /* Group ID of the file's group. */
    unsigned long st_rdev; /* Device number, if device.  */
    unsigned long __pad1;
    long st_size; /* Size of file, in bytes.  */
    int st_blksize; /* Optimal block size for I/O.  */
    int __pad2;
    long st_blocks; /* Number 512-byte blocks allocated. */
    long st_atime; /* Time of last access.  */
    unsigned long st_atime_nsec;
    long st_mtime; /* Time of last modification.  */
    unsigned long st_mtime_nsec;
    long st_ctime; /* Time of last status change.  */
    unsigned long st_ctime_nsec;
    unsigned int __unused4;
    unsigned int __unused5;
};

static void handler_fstat(hook_fargs6_t *args, void *udata)
{
    // copy to user len
    // args->local.data0 = 0;

    char __user *ufilename = (char __user *)syscall_argn(args, 1);
    char filename[128];
    int flen = compact_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;
}

static long minit(const char *args, const char *event, void *__user reserved)
{
    hook_err_t rc = fp_hook_syscalln(__NR3264_fstatat, 4, handler_fstat, 0, (void *)__NR3264_fstatat);
    pr_info("hook rc: %d\n", rc);

    return 0;
}

static long mcontrol0(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

static long mexit(void *__user reserved)
{
    return 0;
}

KPM_INIT(minit);
KPM_CTL0(mcontrol0);
KPM_EXIT(mexit);
