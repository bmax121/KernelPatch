// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * The ko is compiled against a fixed KMI, so struct cred fields are directly
 * addressable (KP's kpimg needs runtime cred_offset instead). Full root =
 * all capabilities + uid/gid switch via a freshly prepared cred. The SELinux
 * translabel helper is resolved at runtime like KP does.
 */
#include "accctl.h"

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/seccomp.h>
#include <linux/spinlock.h>
#include <linux/thread_info.h>
#include <linux/version.h>
#include <linux/sched/task.h>
#include <linux/task_work.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"
#include "../infra/symbol_resolver.h"

/* security_secctx_to_secid is EXPORT_SYMBOL on 5.15 — link it directly. */
extern int security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid);

/* selinux_blob_sizes is a global; resolve via kallsyms. cred->security is a
 * pointer to the LSM cred blob; the selinux part lives at +lbs_cred. */
struct kp_lsm_blob_sizes {
	int lbs_cred;
	int lbs_file;
	int lbs_inode;
	int lbs_superblock;
	int lbs_ipc;
	int lbs_msg_msg;
	int lbs_task;
};

static struct kp_lsm_blob_sizes *kp_selinux_blob_sizes;

typedef int (*kp_task_work_add_t)(struct task_struct *task, struct callback_head *work,
				  enum task_work_notify_mode mode);

static kp_task_work_add_t kp_task_work_add;

/* task_security_struct { osid, sid, ... } — RANDSTRUCT is off, so sid is the
 * second u32 (offset 4). */
struct kp_task_sec {
	u32 osid;
	u32 sid;
};

/*
 * Disable seccomp enforcement for the current task without manually releasing
 * its filter. The filter reference remains owned by current and is released
 * through the normal task-exit path.
 *
 * This deliberately avoids calling seccomp_filter_release(): its internal
 * teardown contract differs across kernel versions and Android GKI backports,
 * and cannot be classified reliably from a generic version check.
 */
static bool kp_disable_current_seccomp(void)
{
	struct sighand_struct *sighand = current->sighand;

	if (!sighand) {
		logkw("seccomp disable skipped: current has no sighand\n");
		return false;
	}

	spin_lock_irq(&sighand->siglock);
#if defined(CONFIG_GENERIC_ENTRY) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	clear_syscall_work(SECCOMP);
#else
	clear_thread_flag(TIF_SECCOMP);
#endif
	current->seccomp.mode = SECCOMP_MODE_DISABLED;
	spin_unlock_irq(&sighand->siglock);

	logkw("seccomp mode disabled; filter retained until task exit\n");
	return true;
}

int kp_accctl_init(void)
{
	kp_task_work_add = (kp_task_work_add_t)kp_resolve_symbol_variant("task_work_add");
	if (!kp_task_work_add)
		logke("failed to resolve task_work_add; task_su disabled\n");

	kp_selinux_blob_sizes = (struct kp_lsm_blob_sizes *)kp_resolve_symbol("selinux_blob_sizes");
	if (!kp_selinux_blob_sizes) {
		logke("failed to resolve selinux_blob_sizes; selinux translabel disabled\n");
		return 0;
	}
	logki("selinux blob sizes: lbs_cred=%d\n", kp_selinux_blob_sizes->lbs_cred);
	return 0;
}

/* Translabel a freshly-prepared cred to the given SELinux context (5.15 has no
 * set_security_override_from_ctx; it was removed in GKI). Resolve the context
 * to a sid and write tsec->sid directly. */
static int kp_selinux_set_cred_context(struct cred *new, const char *sctx)
{
	struct kp_task_sec *tsec;
	u32 sid = 0;
	int rc;

	if (!kp_selinux_blob_sizes || !sctx || !sctx[0])
		return -EINVAL;

	rc = security_secctx_to_secid(sctx, strlen(sctx), &sid);
	if (rc || !sid) {
		logkw("secctx_to_secid(%s) failed: %d sid=%u\n", sctx, rc, sid);
		return rc ? rc : -EINVAL;
	}

	tsec = (struct kp_task_sec *)((char *)new->security + kp_selinux_blob_sizes->lbs_cred);
	tsec->sid = sid;
	return 0;
}

/* Fill every capability in a kernel_cap_t. */
static void fill_caps(struct cred *new)
{
	kernel_cap_t all = CAP_FULL_SET;
	new->cap_effective = all;
	new->cap_permitted = all;
	new->cap_inheritable = all;
	new->cap_bset = all;
	new->cap_ambient = all;
}

static void su_cred(struct cred *new, uid_t uid)
{
	fill_caps(new);
	new->uid = make_kuid(current_user_ns(), uid);
	new->euid = new->uid;
	new->fsuid = new->uid;
	new->suid = new->uid;
	new->gid = make_kgid(current_user_ns(), uid);
	new->egid = new->gid;
	new->fsgid = new->gid;
	new->sgid = new->gid;
}

/* no_sanitize("cfi") keeps indirect calls in this function from tripping
 * __cfi_check on traditional-CFI 5.15 kernels. */
__attribute__((no_sanitize("cfi")))
static int commit_common_su(uid_t to_uid, const char *sctx)
{
	struct cred *new = prepare_creds();
	if (!new)
		return -ENOMEM;

	su_cred(new, to_uid);

	/* Translabel to sctx (e.g. u:r:magisk:s0 / u:r:kp:s0). Without this the
	 * granted process keeps its untrusted_app SELinux domain while running as
	 * uid 0 with all caps — Android blocks it and the app fails to open. If
	 * translabel fails, abort the creds so the caller falls back to another
	 * domain instead of committing an untranslabelled root. */
	if (sctx && sctx[0]) {
		int rc = kp_selinux_set_cred_context(new, sctx);
		if (rc) {
			logkw("selinux set context(%s) failed: %d\n", sctx, rc);
			abort_creds(new);
			return rc;
		}
	}

	commit_creds(new);
	return 0;
}

__attribute__((no_sanitize("cfi")))
int kp_commit_su(uid_t to_uid, const char *sctx)
{
	int rc;

	/* Empty sctx: default to the magisk domain (KP initializes all_allow_sctx
	 * to ALL_ALLOW_SCONTEXT_MAGISK). The u:r:kernel:s0 domain cannot connect
	 * sockets or run ART (seen: libsu RootServer ClassNotFoundException after
	 * Natives.su(0,null) granted kernel cred). Use the fully-qualified
	 * u:r:magisk:s0, resolved via security_secctx_to_secid. Fall back to
	 * kernel cred only if the domain is unavailable. */
	if (!sctx || !sctx[0]) {
		if (kp_selinux_blob_sizes) {
			rc = commit_common_su(to_uid, ALL_ALLOW_SCONTEXT_MAGISK);
			if (!rc) {
				kp_disable_current_seccomp();
				logki("commit_su: to_uid=%u magisk domain\n", to_uid);
				return 0;
			}
			logkw("magisk domain translabel failed (%d), kernel cred fallback\n", rc);
		}
		struct cred *new = prepare_kernel_cred(NULL);
		if (!new)
			return -ENOMEM;
		commit_creds(new);
		kp_disable_current_seccomp();
		logki("commit_su: to_uid=%u kernel cred (u:r:kernel:s0)\n", to_uid);
		return 0;
	}

	/* Explicit sctx: try the translabel, fall back to kernel cred if it fails
	 * so the caller still gets root. */
	rc = commit_common_su(to_uid, sctx);
	if (rc) {
		logkw("commit_common_su failed (%d), falling back to kernel cred\n", rc);
		struct cred *new = prepare_kernel_cred(NULL);
		if (!new)
			return -ENOMEM;
		commit_creds(new);
		kp_disable_current_seccomp();
		return 0;
	}
	kp_disable_current_seccomp();
	return 0;
}

struct kp_task_su_work {
	struct callback_head work;
	uid_t to_uid;
	char *sctx;
};

/* Run credential changes in the target task's own context. */
__attribute__((no_sanitize("cfi")))
static void kp_task_su_workfn(struct callback_head *head)
{
	struct kp_task_su_work *work = container_of(head, struct kp_task_su_work, work);
	struct cred *new;
	int rc;

	if (current->flags & PF_EXITING)
		goto out;

	rc = commit_common_su(work->to_uid, work->sctx);
	if (rc) {
		logkw("task_su: credential setup failed (%d), kernel cred fallback\n", rc);
		new = prepare_kernel_cred(NULL);
		if (new)
			commit_creds(new);
		else
			logke("task_su: kernel cred fallback failed\n");
	}

	logki("task_su: pid %d -> uid %u\n", task_pid_nr(current), work->to_uid);
out:
	kfree(work->sctx);
	kfree(work);
}

__attribute__((no_sanitize("cfi")))
int kp_task_su(pid_t pid, uid_t to_uid, const char *sctx)
{
	struct task_struct *task;
	struct kp_task_su_work *work;
	int rc;

	if (!kp_task_work_add)
		return -ENOSYS;

	task = find_get_task_by_vpid(pid);
	if (!task) {
		logke("task_su: no task pid %d\n", pid);
		return -ESRCH;
	}

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work) {
		put_task_struct(task);
		return -ENOMEM;
	}
	work->to_uid = to_uid;
	if (sctx && sctx[0]) {
		work->sctx = kstrdup(sctx, GFP_KERNEL);
		if (!work->sctx) {
			kfree(work);
			put_task_struct(task);
			return -ENOMEM;
		}
	}
	init_task_work(&work->work, kp_task_su_workfn);

	/* TWA_SIGNAL requests prompt execution when the target is in the kernel. */
	rc = kp_task_work_add(task, &work->work, TWA_SIGNAL);
	put_task_struct(task);
	if (rc) {
		kfree(work->sctx);
		kfree(work);
		logkw("task_su: failed to queue work for pid %d: %d\n", pid, rc);
		return rc;
	}

	logki("task_su: credential update queued for pid %d -> uid %u\n", pid, to_uid);
	return 0;
}
