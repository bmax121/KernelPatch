/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Shim that redirects KP's freestanding <ktypes.h> to the real kernel headers,
 * so the shared uapi header (user/uapi/scdefs.h) compiles unmodified inside
 * the LKM. The ko does not use KP's hand-rolled types; linux/types.h provides
 * the integer types and uid_t, linux/compiler.h provides __user/__force.
 */
#ifndef _KP_KTYPES_H_
#define _KP_KTYPES_H_
#include <linux/types.h>
#include <linux/compiler.h>
#endif
