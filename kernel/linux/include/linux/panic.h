/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PANIC_H
#define _LINUX_PANIC_H

#include <compiler.h>
#include <ksyms.h>

extern void kfunc_def(panic)(const char *fmt, ...) __noreturn __cold;

#define panic(fmt, ...) kfunc(panic)(fmt, ##__VA_ARGS__)

#define panic_kfunc_unexpected() panci("%s", __func__)

#endif