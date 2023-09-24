#ifndef _KP_ACCCTL_H_
#define _KP_ACCCTL_H_

#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

int commit_kernel_cred();
int commit_su(const char *sctx);
int thread_su(pid_t vpid, const char *sctx);

int add_allow_uid(uid_t uid);
int remove_allow_uid(uid_t uid);
int list_allow_uids(uid_t *uids, int *size);

int su_compat_init();
int selinux_hook_install();
int supercall_install();

#endif