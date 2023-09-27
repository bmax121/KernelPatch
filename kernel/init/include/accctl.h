#ifndef _KP_ACCCTL_H_
#define _KP_ACCCTL_H_

#include <ktypes.h>
#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

#define SU_ALLOW_MAX

int make_cred_su(struct cred *cred, const char *sctx);
int commit_kernel_cred();
int effect_su_unsafe(const char *sctx);
int commit_su(int super, const char *sctx);
int thread_su(pid_t vpid, const char *sctx);

int add_allow_uid(uid_t uid);
int remove_allow_uid(uid_t uid);
int list_allow_uids(uid_t *uids, size_t *size);

int su_compat_init();
int selinux_hook_install();
int supercall_install();

#endif