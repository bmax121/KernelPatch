#ifndef __LINUX_PREEMPT_H
#define __LINUX_PREEMPT_H

#include <compiler.h>

/*
 * We put the hardirq and softirq counter into the preemption
 * counter. The bitmask has the following meaning:
 *
 * - bits 0-7 are the preemption count (max preemption depth: 256)
 * - bits 8-15 are the softirq count (max # of softirqs: 256)
 *
 * The hardirq count could in theory be the same as the number of
 * interrupts in the system, but we run all interrupt handlers with
 * interrupts disabled, so we cannot have nesting interrupts. Though
 * there are a few palaeontologic drivers which reenable interrupts in
 * the handler, so we need more than one bit here.
 *
 *         PREEMPT_MASK:	0x000000ff
 *         SOFTIRQ_MASK:	0x0000ff00
 *         HARDIRQ_MASK:	0x000f0000
 *             NMI_MASK:	0x00f00000
 * PREEMPT_NEED_RESCHED:	0x80000000
 */
#define PREEMPT_BITS 8
#define SOFTIRQ_BITS 8
#define HARDIRQ_BITS 4
#define NMI_BITS 4

#define PREEMPT_SHIFT 0
#define SOFTIRQ_SHIFT (PREEMPT_SHIFT + PREEMPT_BITS)
#define HARDIRQ_SHIFT (SOFTIRQ_SHIFT + SOFTIRQ_BITS)
#define NMI_SHIFT (HARDIRQ_SHIFT + HARDIRQ_BITS)

#define __IRQ_MASK(x) ((1UL << (x)) - 1)

#define PREEMPT_MASK (__IRQ_MASK(PREEMPT_BITS) << PREEMPT_SHIFT)
#define SOFTIRQ_MASK (__IRQ_MASK(SOFTIRQ_BITS) << SOFTIRQ_SHIFT)
#define HARDIRQ_MASK (__IRQ_MASK(HARDIRQ_BITS) << HARDIRQ_SHIFT)
#define NMI_MASK (__IRQ_MASK(NMI_BITS) << NMI_SHIFT)

#define PREEMPT_OFFSET (1UL << PREEMPT_SHIFT)
#define SOFTIRQ_OFFSET (1UL << SOFTIRQ_SHIFT)
#define HARDIRQ_OFFSET (1UL << HARDIRQ_SHIFT)
#define NMI_OFFSET (1UL << NMI_SHIFT)

#define SOFTIRQ_DISABLE_OFFSET (2 * SOFTIRQ_OFFSET)

#define PREEMPT_DISABLED (PREEMPT_DISABLE_OFFSET + PREEMPT_ENABLED)

/*
 * Disable preemption until the scheduler is running -- use an unconditional
 * value so that it also works on !PREEMPT_COUNT kernels.
 *
 * Reset by start_kernel()->sched_init()->init_idle()->init_idle_preempt_count().
 */
#define INIT_PREEMPT_COUNT PREEMPT_OFFSET

/*
 * Initial preempt_count value; reflects the preempt_count schedule invariant
 * which states that during context switches:
 *
 *    preempt_count() == 2*PREEMPT_DISABLE_OFFSET
 *
 * Note: PREEMPT_DISABLE_OFFSET is 0 for !PREEMPT_COUNT kernels.
 * Note: See finish_task_switch().
 */
#define FORK_PREEMPT_COUNT (2 * PREEMPT_DISABLE_OFFSET + PREEMPT_ENABLED)

#define preempt_count_add(val) __preempt_count_add(val)
#define preempt_count_sub(val) __preempt_count_sub(val)
#define preempt_count_dec_and_test() __preempt_count_dec_and_test()

#define __preempt_count_inc() __preempt_count_add(1)
#define __preempt_count_dec() __preempt_count_sub(1)

#define preempt_count_inc() preempt_count_add(1)
#define preempt_count_dec() preempt_count_sub(1)

#define preempt_disable()    \
    do {                     \
        preempt_count_inc(); \
        barrier();           \
    } while (0)

#define sched_preempt_enable_no_resched() \
    do {                                  \
        barrier();                        \
        preempt_count_dec();              \
    } while (0)

#define preempt_enable_no_resched() sched_preempt_enable_no_resched()

#define preemptible() (preempt_count() == 0 && !irqs_disabled())

#endif