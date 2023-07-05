#ifndef __LINUX_RWLOCK_H
#define __LINUX_RWLOCK_H

#include <ktypes.h>
#include <compiler.h>
#include <stdint.h>

// todo: arch, enough size
typedef struct
{
    volatile unsigned int lock;
} arch_rwlock_t;

typedef struct
{
    arch_rwlock_t raw_lock;
} rwlock_t;

#define __RW_LOCK_UNLOCKED() \
    (rwlock_t)               \
    {                        \
        .raw_lock = { 0, 0 } \
    }

#define DEFINE_RWLOCK(x) rwlock_t x = __RW_LOCK_UNLOCKED()

#define rwlock_init(_lockp)              \
    do {                                 \
        *(_lockp) = __RW_LOCK_UNLOCKED() \
    } while (0);

#endif
