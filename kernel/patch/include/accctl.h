#ifndef _KP_ACCCTL_H_
#define _KP_ACCCTL_H_

#include <ktypes.h>
#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

#define SU_ALLOW_MAX

int set_selinx_allow(struct task_struct *task, int val);
int commit_kernel_cred();
int effect_su_unsafe(const char *sctx);
int commit_su(int super, const char *sctx);
int thread_su(pid_t vpid, const char *sctx);

int selinux_hook_install();
int supercall_install();

#ifdef ANDROID
int kpuserd_init();
int su_compat_init();
int su_add_allow_uid(uid_t uid);
int su_remove_allow_uid(uid_t uid);
int su_allow_uid_nums();
int su_list_allow_uids(uid_t *__user uids, int num);
int su_reset_path(const char *path);
int su_get_path(char *__user cmd, int size);
long supercall_android(long cmd, long arg1, long arg2, long arg3);
#endif

#endif