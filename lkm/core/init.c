// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KernelPatch LKM entry. Loads via insmod, resolves symbols, scans for the
 * trusted APatch manager, and hooks syscall 45 as the supercall channel.
 */
#include <linux/module.h>
#include <linux/version.h>

#include "../include/kp_lkm.h"
#include "../infra/patch_memory.h"
#include "../infra/symbol_resolver.h"
#include "../infra/syscall_table.h"
#include "../hook/hook_runtime.h"
#include "../manager/manager.h"
#include "../supercall/accctl.h"
#include "../supercall/kstorage.h"
#include "../supercall/sucompat.h"
#include "../supercall/sucompat_hook.h"
#include "../supercall/supercall.h"
#include "../kpm/module.h"
#include "../infra/secpass.h"

/*
 * Some A12-5.10 third-party kernels advertise CC_HAVE_STACKPROTECTOR_SYSREG but
 * don't provide __stack_chk_guard for modules; the DDK toolchain then generates
 * references to it. Manually provide it (same workaround as KernelSU).
 */
#if defined(CONFIG_STACKPROTECTOR) && defined(CONFIG_ARM64) && defined(MODULE) && \
    !defined(CONFIG_STACKPROTECTOR_PER_TASK)
#include <linux/random.h>
#include <linux/stackprotector.h>

unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init setup_stack_chk_guard(void)
{
	unsigned long canary;
	get_random_bytes(&canary, sizeof(canary));
	canary ^= LINUX_VERSION_CODE;
	canary &= CANARY_MASK;
	__stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelpatch_init_early(void)
{
	asm("mov x19, x30;"
	    "bl setup_stack_chk_guard;"
	    "mov x30, x19;"
	    "b kernelpatch_init;");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

int __init kernelpatch_init(void)
{
	int rc;

	logki("KernelPatch LKM loading (version %x, kernel %x)\n", kpver, (unsigned)LINUX_VERSION_CODE);

	kp_symres_init();

	rc = kp_syscall_table_init();
	if (rc)
		return rc;

	rc = kp_patch_memory_init();
	if (rc)
		return rc;

	rc = kp_kstorage_init();
	if (rc)
		return rc;

	rc = kp_accctl_init();
	if (rc)
		return rc;

	rc = kp_sucompat_init();
	if (rc)
		return rc;

	/* Auto-apply APatch config (su path + package allowlist) from
	 * /data/adb/ap. Only used on jailbroken devices where those files exist
	 * at insmod time; the supercall path remains the manager's fallback. */
	kp_su_load_config();

	rc = kp_hook_runtime_init();
	if (rc)
		/* No executable-memory path for hook trampolines (set_memory_x and
		 * execmem_alloc both missing). Continuing would call a NULL allocator
		 * and crash the kernel; fail the load cleanly instead. */
		return rc;

	rc = kp_bypass_kcfi();
	if (rc)
		logkw("CFI bypass failed: %d\n", rc);

	rc = kp_kpm_init();
	if (rc)
		logkw("kpm loader init failed: %d (KPM supercalls will return -ENOSYS)\n", rc);

	rc = kp_supercall_install();
	if (rc)
		return rc;

	rc = kp_sucompat_hook_init();
	if (rc)
		return rc;

	/* Synchronous manager scan; runs in the caller's (root) context so SELinux
	 * allows reading /data. The appid may still be invalid if the manager is
	 * not installed yet; the supercall handler re-checks per call. */
	kp_manager_init();

	/* Re-derive the manager uid when the package manager swaps in a fresh
	 * packages.list (e.g. after the manager app is updated/reinstalled). */
	hook_rename_lsm();

	logki("KernelPatch LKM ready\n");
	return 0;
}

static void __exit kernelpatch_exit(void)
{
	kp_sucompat_hook_exit();
	hook_rename_lsm_exit();
	kp_supercall_uninstall();
	/* Unhook the CFI bypass last so it shields the other teardown from
	 * spurious CFI failures on LKM/KPM text. */
	kp_bypass_kcfi_exit();
	logki("KernelPatch LKM unloaded\n");
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelpatch_init_early);
#else
module_init(kernelpatch_init);
#endif
module_exit(kernelpatch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelPatch LKM");
MODULE_VERSION(KP_LKM_VERSION_STRING);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
