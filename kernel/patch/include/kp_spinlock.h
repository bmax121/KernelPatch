/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KP_SPINLOCK_H
#define __KP_SPINLOCK_H

#include <linux/spinlock.h>

/*
 * These helpers are only for zero-initialized, KP-owned locks. The local
 * fallback uses a 0/1 test-and-set encoding and must not be used with locks
 * owned by the target kernel.
 */
unsigned long kp_private_spin_lock(spinlock_t *lock);
void kp_private_spin_unlock(spinlock_t *lock, unsigned long flags);

#endif
