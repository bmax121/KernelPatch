/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_HOTPATCH_H_
#define _KP_LKM_HOTPATCH_H_
#include <linux/types.h>
int hotpatch(void *addrs[], u32 values[], int count);
#endif
