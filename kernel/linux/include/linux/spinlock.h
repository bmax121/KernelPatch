#ifndef __LINUX_SPINLOCK_H
#define __LINUX_SPINLOCK_H
#define __LINUX_INSIDE_SPINLOCK_H

#include <ktypes.h>
#include <compiler.h>
#include <stdint.h>
#include <ksyms.h>
#include <linux/rwlock.h>

typedef atomic_t arch_spinlock_t;

// todo: preempt

// todo: enough size
typedef struct raw_spinlock
{
    arch_spinlock_t raw_lock;
} raw_spinlock_t;

typedef struct spinlock
{
    union
    {
        struct raw_spinlock rlock;
    };
} spinlock_t;

#define __RAW_SPIN_LOCK_INITIALIZER()

#define __SPIN_LOCK_UNLOCKED() (spinlock_t){ .rlock = { .raw_lock = ATOMIC_INIT(0) } };

#define DEFINE_SPINLOCK(x) spinlock_t x = __SPIN_LOCK_UNLOCKED()

#define spin_lock_init(_lockp)              \
    do {                                    \
        *(_lockp) = __SPIN_LOCK_UNLOCKED(); \
    } while (0)

extern int _atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock);
#define atomic_dec_and_lock(atomic, lock) __cond_lock(lock, _atomic_dec_and_lock(atomic, lock))

extern int kfunc_def(_raw_spin_trylock)(raw_spinlock_t *lock);
extern int kfunc_def(_raw_spin_trylock_bh)(raw_spinlock_t *lock);
extern void kfunc_def(_raw_spin_lock)(raw_spinlock_t *lock);
extern unsigned long kfunc_def(_raw_spin_lock_irqsave)(raw_spinlock_t *lock);
extern void kfunc_def(_raw_spin_lock_irq)(raw_spinlock_t *lock);
extern void kfunc_def(_raw_spin_lock_bh)(raw_spinlock_t *lock);
extern void kfunc_def(_raw_spin_unlock)(raw_spinlock_t *lock);
extern void kfunc_def(_raw_spin_unlock_irqrestore)(raw_spinlock_t *lock, unsigned long flags);
extern void kfunc_def(_raw_spin_unlock_irq)(raw_spinlock_t *lock);
extern void kfunc_def(_raw_spin_unlock_bh)(raw_spinlock_t *lock);

extern int kfunc_def(_raw_read_trylock)(rwlock_t *lock);
extern void kfunc_def(_raw_read_lock)(rwlock_t *lock);
extern unsigned long kfunc_def(_raw_read_lock_irqsave)(rwlock_t *lock);
extern void kfunc_def(_raw_read_lock_irq)(rwlock_t *lock);
extern void kfunc_def(_raw_read_lock_bh)(rwlock_t *lock);
extern void kfunc_def(_raw_read_unlock)(rwlock_t *lock);
extern void kfunc_def(_raw_read_unlock_irqrestore)(rwlock_t *lock, unsigned long flags);
extern void kfunc_def(_raw_read_unlock_irq)(rwlock_t *lock);
extern void kfunc_def(_raw_read_unlock_bh)(rwlock_t *lock);
extern int kfunc_def(_raw_write_trylock)(rwlock_t *lock);
extern void kfunc_def(_raw_write_lock)(rwlock_t *lock);
extern unsigned long kfunc_def(_raw_write_lock_irqsave)(rwlock_t *lock);
extern void kfunc_def(_raw_write_lock_irq)(rwlock_t *lock);
extern void kfunc_def(_raw_write_lock_bh)(rwlock_t *lock);
extern void kfunc_def(_raw_write_unlock)(rwlock_t *lock);
extern void kfunc_def(_raw_write_unlock_irqrestore)(rwlock_t *lock, unsigned long flags);
extern void kfunc_def(_raw_write_unlock_irq)(rwlock_t *lock);
extern void kfunc_def(_raw_write_unlock_bh)(rwlock_t *lock);

static inline int raw_spin_trylock(raw_spinlock_t *lock)
{
    kfunc_direct_call(_raw_spin_trylock, lock);
}

static inline int spin_trylock(spinlock_t *lock)
{
    return raw_spin_trylock(&lock->rlock);
}

static inline int raw_spin_trylock_bh(raw_spinlock_t *lock)
{
    kfunc_direct_call(_raw_spin_trylock_bh, lock);

    return 0;
}
static inline int spin_trylock_bh(spinlock_t *lock)
{
    return raw_spin_trylock_bh(&lock->rlock);
}

static inline void raw_spin_lock(raw_spinlock_t *lock)
{
    kfunc_direct_call(_raw_spin_lock, lock);
}

static inline void spin_lock(spinlock_t *lock)
{
    return raw_spin_lock(&lock->rlock);
}

static inline unsigned long raw_spin_lock_irqsave(raw_spinlock_t *lock)
{
    kfunc_direct_call(_raw_spin_lock_irqsave, lock);
}

static inline unsigned long spin_lock_irqsave(spinlock_t *lock)
{
    return raw_spin_lock_irqsave(&lock->rlock);
}

static inline void raw_spin_lock_irq(raw_spinlock_t *lock)
{
    kfunc_direct_call(_raw_spin_lock_irq, lock);
}

static inline void spin_lock_irq(spinlock_t *lock)
{
    raw_spin_lock_irq(&lock->rlock);
}

static inline void raw_spin_lock_bh(raw_spinlock_t *lock)
{
    kfunc_direct_call(_raw_spin_lock_bh, lock);
}

static inline void spin_lock_bh(spinlock_t *lock)
{
    raw_spin_lock_bh(&lock->rlock);
}

static inline void raw_spin_unlock(raw_spinlock_t *lock)
{
    kfunc_direct_call(_raw_spin_unlock, lock);
}

static inline void spin_unlock(spinlock_t *lock)
{
    raw_spin_unlock(&lock->rlock);
}

static inline void raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
{
    kfunc_direct_call(_raw_spin_unlock_irqrestore, lock, flags);
}

static inline void spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
    raw_spin_unlock_irqrestore(&lock->rlock, flags);
}

static inline void raw_spin_unlock_irq(raw_spinlock_t *lock)
{
    kfunc_direct_call(_raw_spin_unlock_irq, lock);
}

static inline void spin_unlock_irq(spinlock_t *lock)
{
    raw_spin_unlock_irq(&lock->rlock);
}

static inline void raw_spin_unlock_bh(raw_spinlock_t *lock)
{
    kfunc_direct_call(_raw_spin_unlock_bh, lock);
}

static inline void spin_unlock_bh(spinlock_t *lock)
{
    raw_spin_unlock_bh(&lock->rlock);
}

static inline int raw_read_trylock(rwlock_t *lock)
{
    kfunc_direct_call(_raw_read_trylock, lock);
}

static inline void raw_read_lock(rwlock_t *lock)
{
    kfunc_direct_call(_raw_read_lock, lock);
}

static inline unsigned long raw_read_lock_irqsave(rwlock_t *lock)
{
    kfunc_direct_call(_raw_read_lock_irqsave, lock);
}

static inline void raw_read_lock_irq(rwlock_t *lock)
{
    kfunc_direct_call(_raw_read_lock_irq, lock);
}

static inline void raw_read_lock_bh(rwlock_t *lock)
{
    kfunc_direct_call(_raw_read_lock_bh, lock);
}

static inline void raw_read_unlock(rwlock_t *lock)
{
    kfunc_direct_call(_raw_read_unlock, lock);
}

static inline void raw_read_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
{
    kfunc_direct_call(_raw_read_unlock_irqrestore, lock, flags);
}

static inline void raw_read_unlock_irq(rwlock_t *lock)
{
    kfunc_direct_call(_raw_read_unlock_irq, lock);
}

static inline void raw_read_unlock_bh(rwlock_t *lock)
{
    kfunc_direct_call(_raw_read_unlock_bh, lock);
}

static inline int raw_write_trylock(rwlock_t *lock)
{
    kfunc_direct_call(_raw_write_trylock, lock);
}

static inline void raw_write_lock(rwlock_t *lock)
{
    kfunc_direct_call(_raw_write_lock, lock);
}

static inline unsigned long raw_write_lock_irqsave(rwlock_t *lock)
{
    kfunc_direct_call(_raw_write_lock_irqsave, lock);
}

static inline void raw_write_lock_irq(rwlock_t *lock)
{
    kfunc_direct_call(_raw_write_lock_irq, lock);
}

static inline void raw_write_lock_bh(rwlock_t *lock)
{
    kfunc_direct_call(_raw_write_lock_bh, lock);
}

static inline void raw_write_unlock(rwlock_t *lock)
{
    kfunc_direct_call(_raw_write_unlock, lock);
}

static inline void raw_write_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
{
    kfunc_direct_call(_raw_write_unlock_irqrestore, lock, flags);
}

static inline void raw_write_unlock_irq(rwlock_t *lock)
{
    kfunc_direct_call(_raw_write_unlock_irq, lock);
}

static inline void raw_write_unlock_bh(rwlock_t *lock)
{
    kfunc_direct_call(_raw_write_unlock_bh, lock);
}

#endif