#ifndef _KP_ACCCTL_H_
#define _KP_ACCCTL_H_

#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

int commit_su_nodep();
int commit_su();
int grant_su(pid_t vpid, bool real);

long supercall(const char *key, long cmd, long arg2, long arg3, long arg4, long arg5);
int supercall_install();

int lsm_hook_install();
int selinux_hook_install();

#endif