/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_SECPASS_H_
#define _KP_LKM_SECPASS_H_

/* Install CFI bypass hooks on report_cfi_failure / __cfi_slowpath_diag.
 * Must be called after kp_hook_runtime_init(). */
int kp_bypass_kcfi(void);

/* Remove the CFI bypass hooks (call last on module exit). */
void kp_bypass_kcfi_exit(void);

#endif
