#ifndef __LINUX_RCUPDATE_H
#define __LINUX_RCUPDATE_H

#include <limits.h>
#include <ktypes.h>
#include <compiler.h>

#define ULONG_CMP_GE(a, b) (ULONG_MAX / 2 >= (a) - (b))
#define ULONG_CMP_LT(a, b) (ULONG_MAX / 2 < (a) - (b))
#define ulong2long(a) (*(long *)(&(a)))
#define USHORT_CMP_GE(a, b) (USHRT_MAX / 2 >= (unsigned short)((a) - (b)))
#define USHORT_CMP_LT(a, b) (USHRT_MAX / 2 < (unsigned short)((a) - (b)))

/* Exported common interfaces */
void call_rcu(struct rcu_head *head, rcu_callback_t func);
void rcu_barrier_tasks(void);
void rcu_barrier_tasks_rude(void);
void synchronize_rcu(void);
struct rcu_gp_oldstate;
unsigned long get_completed_synchronize_rcu(void);
void get_completed_synchronize_rcu_full(struct rcu_gp_oldstate *rgosp);

void __rcu_read_lock(void);
void __rcu_read_unlock(void);

void rcu_read_unlock_strict(void);

/* Internal to kernel */
void rcu_init(void);
extern int rcu_scheduler_active;
void rcu_sched_clock_irq(int user);
void rcu_report_dead(unsigned int cpu);
void rcutree_migrate_callbacks(int cpu);

void rcu_init_tasks_generic(void);

void rcu_sysrq_start(void);
void rcu_sysrq_end(void);
void rcu_irq_work_resched(void);

void rcu_init_nohz(void);
int rcu_nocb_cpu_offload(int cpu);
int rcu_nocb_cpu_deoffload(int cpu);
void rcu_nocb_flush_deferred_wakeup(void);

void exit_tasks_rcu_start(void);
void exit_tasks_rcu_stop(void);
void exit_tasks_rcu_finish(void);

/*
 * Helper functions for rcu_dereference_check(), rcu_dereference_protected()
 * and rcu_assign_pointer().  Some of these could be folded into their
 * callers, but they are left separate in order to ease introduction of
 * multiple pointers markings to match different RCU implementations
 * (e.g., __srcu), should this make sense in the future.
 */

#ifdef __CHECKER__
#define rcu_check_sparse(p, space) ((void)(((typeof(*p) space *)p) == p))
#else /* #ifdef __CHECKER__ */
#define rcu_check_sparse(p, space)
#endif /* #else #ifdef __CHECKER__ */
#define __unrcu_pointer(p, local)                     \
    ({                                                \
        typeof(*p) *local = (typeof(*p) *__force)(p); \
        rcu_check_sparse(p, __rcu);                   \
        ((typeof(*p) __force __kernel *)(local));     \
    })
/**
 * unrcu_pointer - mark a pointer as not being RCU protected
 * @p: pointer needing to lose its __rcu property
 *
 * Converts @p from an __rcu pointer to a __kernel pointer.
 * This allows an __rcu pointer to be used with xchg() and friends.
 */
#define unrcu_pointer(p) __unrcu_pointer(p, __UNIQUE_ID(rcu))

#define __rcu_access_pointer(p, local, space)                  \
    ({                                                         \
        typeof(*p) *local = (typeof(*p) *__force)READ_ONCE(p); \
        rcu_check_sparse(p, space);                            \
        ((typeof(*p) __force __kernel *)(local));              \
    })

#define __rcu_dereference_check(p, local, c, space)                         \
    ({                                                                      \
        /* Dependency order vs. p above. */                                 \
        typeof(*p) *local = (typeof(*p) *__force)READ_ONCE(p);              \
        RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_check() usage"); \
        rcu_check_sparse(p, space);                                         \
        ((typeof(*p) __force __kernel *)(local));                           \
    })

#define __rcu_dereference_protected(p, local, c, space)                         \
    ({                                                                          \
        RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_protected() usage"); \
        rcu_check_sparse(p, space);                                             \
        ((typeof(*p) __force __kernel *)(p));                                   \
    })

#define __rcu_dereference_raw(p, local)           \
    ({                                            \
        /* Dependency order vs. p above. */       \
        typeof(p) local = READ_ONCE(p);           \
        ((typeof(*p) __force __kernel *)(local)); \
    })
#define rcu_dereference_raw(p) __rcu_dereference_raw(p, __UNIQUE_ID(rcu))

/**
 * RCU_INITIALIZER() - statically initialize an RCU-protected global variable
 * @v: The value to statically initialize with.
 */
#define RCU_INITIALIZER(v) (typeof(*(v)) __force __rcu *)(v)

#define rcu_assign_pointer(p, v)                                          \
    do {                                                                  \
        uintptr_t _r_a_p__v = (uintptr_t)(v);                             \
        rcu_check_sparse(p, __rcu);                                       \
                                                                          \
        if (__builtin_constant_p(v) && (_r_a_p__v) == (uintptr_t)NULL)    \
            WRITE_ONCE((p), (typeof(p))(_r_a_p__v));                      \
        else                                                              \
            smp_store_release(&p, RCU_INITIALIZER((typeof(p))_r_a_p__v)); \
    } while (0)

#define rcu_replace_pointer(rcu_ptr, ptr, c)                           \
    ({                                                                 \
        typeof(ptr) __tmp = rcu_dereference_protected((rcu_ptr), (c)); \
        rcu_assign_pointer((rcu_ptr), (ptr));                          \
        __tmp;                                                         \
    })

#define rcu_access_pointer(p) __rcu_access_pointer((p), __UNIQUE_ID(rcu), __rcu)

#define rcu_dereference_check(p, c) __rcu_dereference_check((p), __UNIQUE_ID(rcu), (c) || rcu_read_lock_held(), __rcu)

#define rcu_dereference_bh_check(p, c) \
    __rcu_dereference_check((p), __UNIQUE_ID(rcu), (c) || rcu_read_lock_bh_held(), __rcu)

#define rcu_dereference_sched_check(p, c) \
    __rcu_dereference_check((p), __UNIQUE_ID(rcu), (c) || rcu_read_lock_sched_held(), __rcu)

#define rcu_dereference_raw_check(p) __rcu_dereference_check((p), __UNIQUE_ID(rcu), 1, __rcu)

#define rcu_dereference_protected(p, c) __rcu_dereference_protected((p), __UNIQUE_ID(rcu), (c), __rcu)

#define rcu_dereference(p) rcu_dereference_check(p, 0)

#define rcu_dereference_bh(p) rcu_dereference_bh_check(p, 0)

#define rcu_dereference_sched(p) rcu_dereference_sched_check(p, 0)

#define rcu_pointer_handoff(p) (p)

static __always_inline void rcu_read_lock(void)
{
    __rcu_read_lock();
    __acquire(RCU);
    rcu_lock_acquire(&rcu_lock_map);
    RCU_LOCKDEP_WARN(!rcu_is_watching(), "rcu_read_lock() used illegally while idle");
}

static inline void rcu_read_unlock(void)
{
    RCU_LOCKDEP_WARN(!rcu_is_watching(), "rcu_read_unlock() used illegally while idle");
    __release(RCU);
    __rcu_read_unlock();
    rcu_lock_release(&rcu_lock_map); /* Keep acq info for rls diags. */
}

static inline void rcu_read_lock_bh(void)
{
    local_bh_disable();
    __acquire(RCU_BH);
    rcu_lock_acquire(&rcu_bh_lock_map);
    RCU_LOCKDEP_WARN(!rcu_is_watching(), "rcu_read_lock_bh() used illegally while idle");
}

static inline void rcu_read_unlock_bh(void)
{
    RCU_LOCKDEP_WARN(!rcu_is_watching(), "rcu_read_unlock_bh() used illegally while idle");
    rcu_lock_release(&rcu_bh_lock_map);
    __release(RCU_BH);
    local_bh_enable();
}

static inline void rcu_read_lock_sched(void)
{
    preempt_disable();
    __acquire(RCU_SCHED);
    rcu_lock_acquire(&rcu_sched_lock_map);
    RCU_LOCKDEP_WARN(!rcu_is_watching(), "rcu_read_lock_sched() used illegally while idle");
}

static inline notrace void rcu_read_lock_sched_notrace(void)
{
    preempt_disable_notrace();
    __acquire(RCU_SCHED);
}

static inline void rcu_read_unlock_sched(void)
{
    RCU_LOCKDEP_WARN(!rcu_is_watching(), "rcu_read_unlock_sched() used illegally while idle");
    rcu_lock_release(&rcu_sched_lock_map);
    __release(RCU_SCHED);
    preempt_enable();
}

static inline notrace void rcu_read_unlock_sched_notrace(void)
{
    __release(RCU_SCHED);
    preempt_enable_notrace();
}

#define RCU_INIT_POINTER(p, v)             \
    do {                                   \
        rcu_check_sparse(p, __rcu);        \
        WRITE_ONCE(p, RCU_INITIALIZER(v)); \
    } while (0)

#define RCU_POINTER_INITIALIZER(p, v) .p = RCU_INITIALIZER(v)

#define __is_kvfree_rcu_offset(offset) ((offset) < 4096)

#define kfree_rcu(ptr, rhf...) kvfree_rcu(ptr, ##rhf)

static inline void rcu_head_init(struct rcu_head *rhp)
{
    rhp->func = (rcu_callback_t)~0L;
}

static inline bool rcu_head_after_call_rcu(struct rcu_head *rhp, rcu_callback_t f)
{
    rcu_callback_t func = READ_ONCE(rhp->func);

    if (func == f)
        return true;
    WARN_ON_ONCE(func != (rcu_callback_t)~0L);
    return false;
}

/* kernel/ksysfs.c definitions */
extern int rcu_expedited;
extern int rcu_normal;

#endif