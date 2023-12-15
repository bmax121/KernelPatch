#ifndef _KP_ACCCTL_H_
#define _KP_ACCCTL_H_

#include <ktypes.h>
#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

int set_priv_selinx_allow(struct task_struct *task, int val);
int commit_kernel_cred();
int commit_su(uid_t uid, const char *sctx);
int task_su(pid_t pid, uid_t to_uid, const char *sctx);

int selinux_hook_install();
int supercall_install();

#ifdef ANDROID
int kpuserd_init();
int su_compat_init();
int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *sctx, int async);
int su_remove_allow_uid(uid_t uid, int async);
int su_allow_uid_nums();
int su_list_allow_uids(char *__user buf, int buf_len);
int su_reset_path(const char *path);
int su_get_path(char *__user ubuf, int buf_len);
long supercall_android(long cmd, long arg1, long arg2, long arg3);
#endif

#endif