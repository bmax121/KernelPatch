/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <kp_spinlock.h>

#include <asm/cmpxchg.h>

static inline bool kp_native_spin_irq_pair_available(void)
{
    return kfunc(_raw_spin_lock_irqsave) && kfunc(_raw_spin_unlock_irqrestore);
}

static inline unsigned long kp_local_irq_save(void)
{
    unsigned long flags;

    asm volatile("mrs %0, daif\n\t"
                 "msr daifset, #2"
                 : "=r"(flags)
                 :
                 : "memory");
    return flags;
}

static inline void kp_local_irq_restore(unsigned long flags)
{
    asm volatile("msr daif, %0" : : "r"(flags) : "memory");
}

static inline void kp_local_raw_spin_lock(raw_spinlock_t *lock)
{
    while (cmpxchg(&lock->raw_lock.counter, 0, 1) != 0) {
        while (__atomic_load_n(&lock->raw_lock.counter, __ATOMIC_RELAXED))
            asm volatile("yield" ::: "memory");
    }
}

static inline void kp_local_raw_spin_unlock(raw_spinlock_t *lock)
{
    smp_store_release(&lock->raw_lock.counter, 0);
}

unsigned long kp_private_spin_lock(spinlock_t *lock)
{
    raw_spinlock_t *raw_lock = &lock->rlock;
    unsigned long flags;

    if (likely(kp_native_spin_irq_pair_available()))
        return kfunc(_raw_spin_lock_irqsave)(raw_lock);

    /* Target preempt-count layouts vary, so the local fallback masks IRQs instead. */
    flags = kp_local_irq_save();
    kp_local_raw_spin_lock(raw_lock);
    return flags;
}

void kp_private_spin_unlock(spinlock_t *lock, unsigned long flags)
{
    raw_spinlock_t *raw_lock = &lock->rlock;

    if (likely(kp_native_spin_irq_pair_available())) {
        kfunc(_raw_spin_unlock_irqrestore)(raw_lock, flags);
        return;
    }

    kp_local_raw_spin_unlock(raw_lock);
    kp_local_irq_restore(flags);
}
