/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Runtime locking correctness validator
 *
 *  Copyright (C) 2006,2007 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *  Copyright (C) 2007 Red Hat, Inc., Peter Zijlstra
 *
 * see Documentation/locking/lockdep-design.rst for more details.
 */
#ifndef __LINUX_LOCKDEP_H
#define __LINUX_LOCKDEP_H

#include <ksyms.h>

struct lockdep_map;

/*
 * Acquire a lock.
 *
 * Values for "read":
 *
 *   0: exclusive (write) acquire
 *   1: read-acquire (no recursion allowed)
 *   2: read-acquire with same-instance recursion allowed
 *
 * Values for check:
 *
 *   0: simple checks (freeing, held-at-exit-time, etc.)
 *   1: full validation
 */
extern void kfunc_def(lock_acquire)(struct lockdep_map *lock, unsigned int subclass, int trylock, int read, int check,
                                    struct lockdep_map *nest_lock, unsigned long ip);
extern void kfunc_def(lock_release)(struct lockdep_map *lock, unsigned long ip);
extern void kfunc_def(lock_sync)(struct lockdep_map *lock, unsigned int subclass, int read, int check,
                                 struct lockdep_map *nest_lock, unsigned long ip);

/* lock_is_held_type() returns */
#define LOCK_STATE_UNKNOWN -1
#define LOCK_STATE_NOT_HELD 0
#define LOCK_STATE_HELD 1

#define lockdep_is_held(lock) lock_is_held(&(lock)->dep_map)
#define lockdep_is_held_type(lock, r) lock_is_held_type(&(lock)->dep_map, (r))

#define lock_set_novalidate_class(l, n, i) lock_set_class(l, n, &__lockdep_no_validate__, 0, i)

#define NIL_COOKIE      \
    (struct pin_cookie) \
    {                   \
        .val = 0U,      \
    }

static inline void lock_acquire(struct lockdep_map *lock, unsigned int subclass, int trylock, int read, int check,
                                struct lockdep_map *nest_lock, unsigned long ip)
{
    kfunc_call_void(lock_acquire, lock, subclass, trylock, read, check, nest_lock, ip);
}

static inline void lock_release(struct lockdep_map *lock, unsigned long ip)
{
    kfunc_call_void(lock_release, lock, ip);
}

static inline void lock_sync(struct lockdep_map *lock, unsigned int subclass, int read, int check,
                             struct lockdep_map *nest_lock, unsigned long ip)
{
    kfunc_call_void(lock_sync, lock, subclass, read, check, nest_lock, ip);
}

#endif