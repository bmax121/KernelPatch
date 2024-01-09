/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_TASKOB_H_
#define _KP_TASKOB_H_

#include <hook.h>

hook_err_t add_execv_hook(hook_chain8_callback before, hook_chain8_callback after, void *udata);
void remove_execv_hook(hook_chain8_callback before, hook_chain8_callback after);

#endif