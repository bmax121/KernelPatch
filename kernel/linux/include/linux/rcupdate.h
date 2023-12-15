#ifndef __LINUX_RCUPDATE_H
#define __LINUX_RCUPDATE_H

#include <ktypes.h>
#include <compiler.h>
#include <linux/lockdep.h>
#include <linux/bottom_half.h>
#include <asm-generic/rwonce.h>

//  todo: macro for compile
#define RCU_LOCKDEP_WARN(c, s)
#define rcu_sleep_check()
//

#define ULONG_CMP_GE(a, b) (ULONG_MAX / 2 >= (a) - (b))
#define ULONG_CMP_LT(a, b) (ULONG_MAX / 2 < (a) - (b))
#define ulong2long(a) (*(long *)(&(a)))
#define USHORT_CMP_GE(a, b) (USHRT_MAX / 2 >= (unsigned short)((a) - (b)))
#define USHORT_CMP_LT(a, b) (USHRT_MAX / 2 < (unsigned short)((a) - (b)))

struct rcu_gp_oldstate;

/* Exported common interfaces */
extern void kfunc_def(call_rcu)(struct rcu_head *head, rcu_callback_t func);
extern void kfunc_def(rcu_barrier_tasks)(void);
extern void kfunc_def(rcu_barrier_tasks_rude)(void);
extern void kfunc_def(synchronize_rcu)(void);
extern unsigned long kfunc_def(get_completed_synchronize_rcu)(void);
extern void kfunc_def(get_completed_synchronize_rcu_full)(struct rcu_gp_oldstate *rgosp);

extern void kfunc_def(__rcu_read_lock)(void);
extern void kfunc_def(__rcu_read_unlock)(void);
extern void kfunc_def(rcu_read_unlock_strict)(void);

/* Internal to kernel */
extern void kfunc_def(rcu_init)(void);
extern void kfunc_def(rcu_sched_clock_irq)(int user);
extern void kfunc_def(rcu_report_dead)(unsigned int cpu);
extern void kfunc_def(rcutree_migrate_callbacks)(int cpu);

extern void kfunc_def(rcu_init_tasks_generic)(void);

extern void kfunc_def(rcu_sysrq_start)(void);
extern void kfunc_def(rcu_sysrq_end)(void);
extern void kfunc_def(rcu_irq_work_resched)(void);

extern int kfunc_def(rcu_read_lock_held)(void);
extern int kfunc_def(rcu_read_lock_bh_held)(void);
extern int kfunc_def(rcu_read_lock_sched_held)(void);
extern int kfunc_def(rcu_read_lock_any_held)(void);

extern void kfunc_def(rcu_init_nohz)(void);
extern int kfunc_def(rcu_nocb_cpu_offload)(int cpu);
extern int kfunc_def(rcu_nocb_cpu_deoffload)(int cpu);
extern void kfunc_def(rcu_nocb_flush_deferred_wakeup)(void);

extern void kfunc_def(exit_tasks_rcu_start)(void);
extern void kfunc_def(exit_tasks_rcu_stop)(void);
extern void kfunc_def(exit_tasks_rcu_finish)(void);

// wrap
static inline void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
    kfunc_call(call_rcu, head, func)
}
static inline void rcu_barrier_tasks(void)
{
    kfunc_call(rcu_barrier_tasks);
}
static inline void rcu_barrier_tasks_rude(void)
{
    kfunc_call(rcu_barrier_tasks_rude)
}
static inline void synchronize_rcu(void)
{
    kfunc_call(rcu_barrier_tasks_rude)
}
static inline unsigned long get_completed_synchronize_rcu(void)
{
    kfunc_call(get_completed_synchronize_rcu)
}
static inline void get_completed_synchronize_rcu_full(struct rcu_gp_oldstate *rgosp)
{
    kfunc_call(get_completed_synchronize_rcu_full, rgosp);
}

static inline void __rcu_read_lock(void)
{
    kfunc_call(__rcu_read_lock);
}
static inline void __rcu_read_unlock(void)
{
    kfunc_call(__rcu_read_unlock);
}
static inline void rcu_read_unlock_strict(void)
{
    kfunc_call(rcu_read_unlock_strict);
}

/* Internal to kernel */
static inline void rcu_init(void)
{
    kfunc_call(rcu_init);
}
static inline void rcu_sched_clock_irq(int user)
{
    kfunc_call(rcu_sched_clock_irq, user);
}
static inline void rcu_report_dead(unsigned int cpu)
{
    kfunc_call(rcu_report_dead, cpu);
}
static inline void rcutree_migrate_callbacks(int cpu)
{
    kfunc_call(rcutree_migrate_callbacks, cpu);
}

static inline void rcu_init_tasks_generic(void)
{
    kfunc_call(rcu_init_tasks_generic);
}

static inline void rcu_sysrq_start(void)
{
    kfunc_call(rcu_sysrq_start);
}
static inline void rcu_sysrq_end(void)
{
    kfunc_call(rcu_sysrq_end);
}
static inline void rcu_irq_work_resched(void)
{
    kfunc_call(rcu_irq_work_resched);
}

static inline int rcu_read_lock_held(void)
{
    kfunc_call(rcu_read_lock_held);
}
static inline int rcu_read_lock_bh_held(void)
{
    kfunc_call(rcu_read_lock_bh_held);
}
static inline int rcu_read_lock_sched_held(void)
{
    kfunc_call(rcu_read_lock_sched_held);
}
static inline int rcu_read_lock_any_held(void)
{
    kfunc_call(rcu_read_lock_any_held);
}

static inline void rcu_init_nohz(void)
{
    kfunc_call(rcu_init_nohz);
}
static inline int rcu_nocb_cpu_offload(int cpu)
{
    kfunc_call(rcu_nocb_cpu_offload, cpu);
}
static inline int rcu_nocb_cpu_deoffload(int cpu)
{
    kfunc_call(rcu_nocb_cpu_deoffload, cpu);
}
static inline void rcu_nocb_flush_deferred_wakeup(void)
{
    kfunc_call(rcu_nocb_flush_deferred_wakeup);
}

static inline void exit_tasks_rcu_start(void)
{
    kfunc_call(exit_tasks_rcu_start);
}
static inline void exit_tasks_rcu_stop(void)
{
    kfunc_call(exit_tasks_rcu_stop);
}
static inline void exit_tasks_rcu_finish(void)
{
    kfunc_call(exit_tasks_rcu_finish);
}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
static inline void rcu_lock_acquire(struct lockdep_map *map)
{
    lock_acquire(map, 0, 0, 2, 0, NULL, _THIS_IP_);
}
static inline void rcu_lock_release(struct lockdep_map *map)
{
    lock_release(map, _THIS_IP_);
}
#else /* #ifdef CONFIG_DEBUG_LOCK_ALLOC */

#define rcu_lock_acquire(a) \
    do {                    \
    } while (0)
#define rcu_lock_release(a) \
    do {                    \
    } while (0)
#endif

#define rcu_check_sparse(p, space) ((void)(((typeof(*p) space *)p) == p))

#define __unrcu_pointer(p, local)                     \
    ({                                                \
        typeof(*p) *local = (typeof(*p) *__force)(p); \
        rcu_check_sparse(p, __rcu);                   \
        ((typeof(*p) __force __kernel *)(local));     \
    })

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
    if (func == f) return true;
    // WARN_ON_ONCE(func != (rcu_callback_t)~0L);
    return false;
}

#endif