// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Intercept execve of the su binary (/system/bin/kp). When a su-allowed or
 * manager uid execs it, grant root inline (kp_commit_su) and redirect the exec
 * to the shell (/system/bin/sh). Ported from KP's handle_before_execve, minus
 * the apd daemon branch (framework).
 */
#include "sucompat_hook.h"
#include "accctl.h"
#include "sucompat.h"

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"
#include "../infra/syscall_table.h"
#include "../manager/manager.h"
#include <hook.h>

#define KP_EXECVE_NR __NR_execve /* 221 on arm64 */
#define KP_SH_PATH SH_PATH       /* /system/bin/sh */

static kp_syscall_fn_t kp_orig_execve;
/* Resolved getname_flags address, kept so the inline hook can be removed on
 * module exit (otherwise rmmod leaves a branch into freed module memory). */
static unsigned long kp_getname_flags_addr;

/* Parse the -Z <sctx> option from a SUPERCMD argv: "truncate <key> -Z <sctx>".
 * Returns a static buffer (KP's profile.scontext) or NULL if absent. */
static const char *kp_get_supercmd_sctx(const struct pt_regs *regs)
{
	static char sctx[SUPERCALL_SCONTEXT_LEN];
	char __user **uargv = (char __user **)regs->regs[1];
	int i;

	if (!uargv)
		return NULL;

	/* argv layout: [0]=truncate [1]=key [2..]=options. Walk args 2.. */
	for (i = 2; i < 16; i++) {
		char __user *arg;
		char buf[64];

		if (copy_from_user(&arg, &uargv[i], sizeof(arg)))
			break;
		if (!arg)
			break;
		if (strncpy_from_user(buf, arg, sizeof(buf)) <= 0)
			break;
		if (buf[0] != '-')
			break; /* options end at first non-option */
		if (buf[1] == 'Z') {
			char __user *sctx_arg;
			if (copy_from_user(&sctx_arg, &uargv[i + 1], sizeof(sctx_arg)))
				break;
			if (!sctx_arg)
				break;
			if (strncpy_from_user(sctx, sctx_arg, sizeof(sctx)) > 0) {
				sctx[sizeof(sctx) - 1] = '\0';
				return sctx;
			}
			break;
		}
	}
	return NULL;
}

/* Grant root and repoint the execve to apd (su only, if installed) or sh.
 * @su_exec: true when the intercepted binary is an actual su invocation (so a
 * -c/-u command must be preserved for apd's root_shell); false for SUPERCMD
 * (truncate <key> -Z <sctx>), which is a plain root shell request that sh
 * should get with no args. Overwrites the caller's user-space filename buffer
 * and argv in place.
 * @sctx: SELinux context to switch to. */
static long kp_redirect_to_sh(const struct pt_regs *regs, const char *what, uid_t uid,
			      bool su_exec, bool manager_exec, const char *sctx)
{
	char __user *ufilename = (char __user *)regs->regs[0];
	char __user **uargv = (char __user **)regs->regs[1];
	const char *target = KP_SH_PATH;
	struct file *fp;
	bool use_apd = false;

	logki("execve %s by uid %u: granting root (sctx=%s)\n", what, uid,
	      sctx ? sctx : "(kernel)");
	kp_commit_su(0, sctx);

	/* apd is the full su daemon (handles -c/-s/-u/-l/-p/pty), so a real su
	 * exec goes to it. SUPERCMD stays on sh: apd's root_shell would parse
	 * the supercmd's "<key> -Z <sctx>" args with getopts and fail, whereas
	 * sh (no args) gives the manager its interactive root shell. */
	/* Keep manager launches on the direct shell path.  APatch uses its own
	 * SUPERCMD/root-shell bootstrap; sending a manager-owned su exec back to
	 * apd re-enters userspace dispatch and breaks that bootstrap.  Granted
	 * applications still need apd so their su arguments are honoured. */
	if (su_exec && !manager_exec) {
		fp = filp_open(APD_PATH, O_RDONLY | O_NOFOLLOW, 0);
		if (!IS_ERR(fp)) {
			filp_close(fp, NULL);
			target = APD_PATH;
			use_apd = true;
		}
	}
	logki("redirect to %s\n", target);

	/* Overwrite the filename buffer with the target path. */
	if (copy_to_user(ufilename, target, strlen(target) + 1)) {
		logkw("failed to overwrite filename buffer\n");
		goto passthrough;
	}

	if (use_apd) {
		/* apd dispatches on argv[0] ending in "su"/"kp": write a su-style
		 * name onto the user stack and repoint argv[0] to it. Keep the
		 * rest of argv intact so apd's root_shell() sees -c/-u/... args. */
		uintptr_t sp = current_user_stack_pointer();
		char __user *arg0;

		sp -= strlen(LEGACY_SU_PATH) + 1;
		sp &= 0xFFFFFFFFFFFFFFF8ULL;
		arg0 = (char __user *)sp;
		if (copy_to_user(arg0, LEGACY_SU_PATH, strlen(LEGACY_SU_PATH) + 1)) {
			logkw("failed to write su argv[0]\n");
			goto passthrough;
		}
		if (copy_to_user(&uargv[0], &arg0, sizeof(arg0))) {
			logkw("failed to rewrite argv[0]\n");
			goto passthrough;
		}
	} else if (su_exec && !manager_exec) {
		/* No apd but a real su: point the exec at sh and keep argv as-is.
		 * sh treats "-c <cmd>" naturally, so "su -c id" still runs the
		 * command instead of dropping it. */
		(void)uargv;
	} else {
		/* Manager and SUPERCMD root shells take no arguments. */
		char __user *nullp = NULL;
		if (copy_to_user(&uargv[1], &nullp, sizeof(nullp))) {
			logkw("failed to rewrite argv[1]\n");
			goto passthrough;
		}
	}

	return kp_orig_execve(regs);

passthrough:
	if (kp_orig_execve)
		return kp_orig_execve(regs);
	return -ENOSYS;
}

/* ---- getname_flags path-probe redirect -------------------------------- */

static void kp_after_getname_flags(hook_fargs4_t *args, void *udata)
{
	struct filename *fn = (struct filename *)args->ret;
	const char *sh_path = SH_PATH;
	const char *su_path;
	size_t sh_len, su_len;

	if (IS_ERR_OR_NULL(fn))
		return;

	{
		uid_t uid = from_kuid(current_user_ns(), current_uid());
		if (!kp_is_su_allow_uid(uid) && !kp_is_manager_uid(uid))
			return;
	}

	su_path = kp_su_get_path();
	if (!fn->name || strcmp(fn->name, su_path))
		return;

	sh_len = strlen(sh_path);
	su_len = strlen(su_path);

	if (sh_len <= su_len) {
		/* New name fits in existing buffer. */
		strscpy((char *)fn->name, sh_path, su_len + 1);
		return;
	}

	/* sh_path is longer: allocate a fresh filename object. */
	{
		typeof(&getname_kernel) kp_getname;
		typeof(&putname) kp_putname;

		kp_getname = (typeof(kp_getname))kallsyms_lookup_name("getname_kernel");
		kp_putname = (typeof(kp_putname))kallsyms_lookup_name("putname");
		if (kp_getname && kp_putname) {
			struct filename *nf = kp_getname(sh_path);
			if (!IS_ERR_OR_NULL(nf)) {
				kp_putname(fn);
				args->ret = (unsigned long)nf;
			}
		}
	}
}

static int kp_hook_getname_flags(void)
{
	unsigned long addr;

	addr = kallsyms_lookup_name("__original_getname_flags");
	if (!addr)
		addr = kallsyms_lookup_name("getname_flags");
	if (!addr) {
		logki("sucompat: getname_flags not found, path-probe unavailable\n");
		return -ENOENT;
	}
	logki("sucompat: getname_flags at %px\n", (void *)addr);
	kp_getname_flags_addr = addr;
	return hook_wrap3((void *)addr, 0, kp_after_getname_flags, 0);
}

/* Default SELinux context */
static const char *kp_default_sctx(uid_t uid)
{
	static char sctx[SUPERCALL_SCONTEXT_LEN];
	struct su_profile profile;

	if (kp_su_allow_uid_profile(uid, &profile) == 0 && profile.scontext[0]) {
		strscpy(sctx, profile.scontext, sizeof(sctx));
		return sctx;
	}
	return ALL_ALLOW_SCONTEXT_MAGISK;
}

static long kp_execve_handler(const struct pt_regs *regs)
{
	uid_t uid = from_kuid(current_user_ns(), current_uid());
	char __user *ufilename = (char __user *)regs->regs[0];
	char filename[SU_PATH_MAX_LEN];
	long flen;
	bool su_ok, mgr_ok;

	/* Debug: log every execve from a su-allowed/manager uid (may be chatty). */
	if (ufilename && (kp_is_su_allow_uid(uid) || kp_is_manager_uid(uid))) {
		flen = strncpy_from_user(filename, ufilename, sizeof(filename));
		if (flen > 0)
			logki("execve uid=%u path=%s (su_path=%s)\n", uid, filename, kp_su_get_path());
		else
			logki("execve uid=%u path=<unreadable> (su_path=%s)\n", uid, kp_su_get_path());
	}

	/* Only su-allowed / manager uids trigger the interception. */
	mgr_ok = kp_is_manager_uid(uid);
	su_ok = kp_is_su_allow_uid(uid);
	if (!su_ok && !mgr_ok)
		goto passthrough;

	if (!ufilename)
		goto passthrough;
	flen = strncpy_from_user(filename, ufilename, sizeof(filename));
	if (flen <= 0)
		goto passthrough;

	/* su binary: match any path an app may exec, not just the configured one.
	 * The manager resets su_path to /system/bin/su at install, but that reset
	 * (SUPERCALL_SU_RESET_PATH) can be missed if the manager wasn't crowned
	 * yet, and some apps exec /system/bin/kp or a bare "su"/"kp" via PATH.
	 * Matching all of them is what makes a granted app actually get root. */
	const char *su_path = kp_su_get_path();
	bool is_su_bin = strcmp(filename, su_path) == 0 ||
			 strcmp(filename, LEGACY_SU_PATH) == 0 ||
			 strcmp(filename, SU_PATH) == 0;
	if (!is_su_bin && (strcmp(filename, "su") == 0 || strcmp(filename, "kp") == 0))
		is_su_bin = true;
	if (is_su_bin)
		return kp_redirect_to_sh(regs, filename, uid, true, mgr_ok,
					 kp_default_sctx(uid));

	/* SUPERCMD (/system/bin/truncate): the manager builds its root shell as
	 * "truncate <key> -Z <sctx>", and shell users run "truncate su". Both the
	 * manager and any su-allowed uid (e.g. shell 2000) may use it. Without
	 * this the exec falls through to the real truncate ("Needs -s") and apd
	 * install fails every boot. */
	if ((su_ok || mgr_ok) && strcmp(filename, SUPERCMD) == 0) {
		const char *sctx = kp_get_supercmd_sctx(regs);
		if (!sctx)
			sctx = kp_default_sctx(uid);
		return kp_redirect_to_sh(regs, filename, uid, false, mgr_ok, sctx);
	}

passthrough:
	if (kp_orig_execve)
		return kp_orig_execve(regs);
	return -ENOSYS;
}

int kp_sucompat_hook_init(void)
{
	int rc = kp_syscall_hook(KP_EXECVE_NR, kp_execve_handler, &kp_orig_execve);
	if (rc)
		return rc;
	logki("sucompat: execve hook installed (su path %s -> %s)\n", kp_su_get_path(), KP_SH_PATH);

	rc = kp_hook_getname_flags();
	if (rc)
		logkfd("sucompat: getname_flags hook failed: %d\n", rc);
	else
		logki("sucompat: getname_flags hook installed\n");
	return 0;
}

void kp_sucompat_hook_exit(void)
{
	kp_syscall_unhook(KP_EXECVE_NR, kp_orig_execve);
	kp_orig_execve = NULL;
	if (kp_getname_flags_addr) {
		/* Installed as hook_wrap3(addr, 0, kp_after_getname_flags, 0); pass the
		 * same (before, after) pair to unwrap so the chain item matches. */
		hook_unwrap((void *)kp_getname_flags_addr, 0, kp_after_getname_flags);
		kp_getname_flags_addr = 0;
	}
}
