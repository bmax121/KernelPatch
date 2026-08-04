/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_KPM_H_
#define _KP_LKM_KPM_H_

#include <linux/types.h>

long kp_kpm_load_sc(const char __user *upath, const char __user *uargs, void __user *reserved);
long kp_kpm_control_sc(const char __user *uname, const char __user *uctl_args,
		       char __user *out_msg, int outlen);
long kp_kpm_unload_sc(const char __user *uname, void __user *reserved);
long kp_kpm_nums_sc(void);
long kp_kpm_list_sc(char __user *names, int len);
long kp_kpm_info_sc(const char __user *uname, char __user *out_info, int out_len);

#endif /* _KP_LKM_KPM_H_ */
