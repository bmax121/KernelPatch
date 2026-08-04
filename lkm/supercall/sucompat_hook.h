/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */
#ifndef _KP_LKM_SUCOMPAT_HOOK_H_
#define _KP_LKM_SUCOMPAT_HOOK_H_

/* Hook __NR_execve to intercept su binary execs. Returns 0 on success. */
int kp_sucompat_hook_init(void);

/* Restore the execve hook. */
void kp_sucompat_hook_exit(void);

#endif /* _KP_LKM_SUCOMPAT_HOOK_H_ */
