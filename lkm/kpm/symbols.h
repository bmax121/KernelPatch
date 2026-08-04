/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_KPM_SYMBOLS_H_
#define _KP_LKM_KPM_SYMBOLS_H_

#include <linux/types.h>

int kp_kpm_symbols_init(void);
unsigned long kp_kpm_symbol_lookup(const char *name);

#endif
