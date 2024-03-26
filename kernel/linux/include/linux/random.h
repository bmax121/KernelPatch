/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/random.h
 *
 * Include file for the random number generator.
 */
#ifndef _LINUX_RANDOM_H
#define _LINUX_RANDOM_H

#include <ktypes.h>
#include <ksyms.h>

extern void kfunc_def(get_random_bytes)(void *buf, int nbytes);
extern uint64_t kfunc_def(get_random_u64)(void);
extern uint64_t kfunc_def(get_random_long)(void);

#endif