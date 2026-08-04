/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_LOG_H_
#define _KP_LKM_LOG_H_

#include <linux/printk.h>

#ifndef logkv
#define logkv(fmt, ...) pr_debug("kernelpatch-lkm: hook: " fmt, ##__VA_ARGS__)
#endif
#ifndef logkd
#define logkd(fmt, ...) pr_debug("kernelpatch-lkm: " fmt, ##__VA_ARGS__)
#endif
#ifndef logkfd
#define logkfd(fmt, ...) pr_debug("kernelpatch-lkm: %s: " fmt, __func__, ##__VA_ARGS__)
#endif
#ifndef logki
#define logki(fmt, ...) pr_info("kernelpatch-lkm: " fmt, ##__VA_ARGS__)
#endif
#ifndef logkfi
#define logkfi(fmt, ...) pr_info("kernelpatch-lkm: %s: " fmt, __func__, ##__VA_ARGS__)
#endif
#ifndef logkw
#define logkw(fmt, ...) pr_warn("kernelpatch-lkm: " fmt, ##__VA_ARGS__)
#endif
#ifndef logke
#define logke(fmt, ...) pr_err("kernelpatch-lkm: " fmt, ##__VA_ARGS__)
#endif
#ifndef logkfe
#define logkfe(fmt, ...) pr_err("kernelpatch-lkm: %s: " fmt, __func__, ##__VA_ARGS__)
#endif

#endif
