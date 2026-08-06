// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KPM supercall handlers. ABI matches kernel/patch/common/supercall.c
 * call_kpm_* and user/uapi/scdefs.h. Strings are copied from user space; the
 * loader works on kernel buffers.
 */
#include "kpm.h"

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"
#include "module.h"

#define KPM_LOAD_PATH_LEN 1024
#define KPM_NAME_LEN 32
#define KPM_CTL_ARGS_LEN 1024

long kp_kpm_load_sc(const char __user *upath, const char __user *uargs, void __user *reserved)
{
	char path[KPM_LOAD_PATH_LEN];
	char *args;
	long pathlen = strncpy_from_user(path, upath, sizeof(path));
	if (pathlen <= 0)
		return -EINVAL;

	args = kzalloc(KPM_ARGS_LEN, GFP_KERNEL);
	if (!args)
		return -ENOMEM;
	long arglen = strncpy_from_user(args, uargs, KPM_ARGS_LEN);
	long rc = kp_load_module_path(path, arglen <= 0 ? NULL : args, reserved);
	kfree(args);
	return rc;
}

long kp_kpm_control_sc(const char __user *uname, const char __user *uctl_args,
		       char __user *out_msg, int outlen)
{
	char name[KPM_NAME_LEN];
	char *ctl_args;
	long namelen = strncpy_from_user(name, uname, sizeof(name));
	if (namelen <= 0)
		return -EINVAL;

	ctl_args = kzalloc(KPM_CTL_ARGS_LEN, GFP_KERNEL);
	if (!ctl_args)
		return -ENOMEM;
	long arglen = strncpy_from_user(ctl_args, uctl_args, KPM_CTL_ARGS_LEN);
	long rc = kp_module_control0(name, arglen <= 0 ? NULL : ctl_args, out_msg, outlen);
	kfree(ctl_args);
	return rc;
}

long kp_kpm_unload_sc(const char __user *uname, void __user *reserved)
{
	char name[KPM_NAME_LEN];
	long len = strncpy_from_user(name, uname, sizeof(name));
	if (len <= 0)
		return -EINVAL;
	return kp_unload_module(name, reserved);
}

long kp_kpm_nums_sc(void)
{
	return kp_get_module_nums();
}

long kp_kpm_list_sc(char __user *names, int len)
{
	if (len <= 0)
		return -EINVAL;
	char *buf = kzalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	int sz = kp_list_modules(buf, 4096);
	if (sz < 0) {
		kfree(buf);
		return sz;
	}
	if (sz > len) {
		kfree(buf);
		return -ENOBUFS;
	}
	int copy_len = sz > 0 ? sz : 1;
	int rc = copy_to_user(names, buf, copy_len) ? -EFAULT : sz;
	kfree(buf);
	return rc;
}

long kp_kpm_info_sc(const char __user *uname, char __user *out_info, int out_len)
{
	if (out_len <= 0)
		return -EINVAL;
	char name[KPM_NAME_LEN];
	char *buf = kzalloc(2048, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	int len = strncpy_from_user(name, uname, sizeof(name));
	if (len <= 0) {
		kfree(buf);
		return -EINVAL;
	}
	int sz = kp_get_module_info(name, buf, 2048);
	if (sz < 0) {
		kfree(buf);
		return sz;
	}
	if (sz > out_len) {
		kfree(buf);
		return -ENOBUFS;
	}
	int rc = copy_to_user(out_info, buf, sz) ? -EFAULT : sz;
	kfree(buf);
	return rc;
}
