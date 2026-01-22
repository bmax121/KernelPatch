#ifndef _LINUX_STOP_MACHINE
#define _LINUX_STOP_MACHINE

#include <ktypes.h>
#include <ksyms.h>

typedef int (*cpu_stop_fn_t)(void *arg);

struct cpumask;

extern const struct cpumask *kvar(__cpu_online_mask);
#define cpu_online_mask kvar(__cpu_online_mask)

/**
 * stop_machine: freeze the machine on all CPUs and run this function
 * @fn: the function to run
 * @data: the data ptr for the @fn()
 * @cpus: the cpus to run the @fn() on (NULL = any online cpu)
 *
 * Description: This causes a thread to be scheduled on every cpu,
 * each of which disables interrupts.  The result is that no one is
 * holding a spinlock or inside any other preempt-disabled region when
 * @fn() runs.
 *
 * This can be thought of as a very heavy write lock, equivalent to
 * grabbing every spinlock in the kernel.
 * 
 * Protects against CPU hotplug.
 * 
 */
extern int kfunc_def(stop_machine)(int (*fn)(void *), void *data, const struct cpumask *cpus);

static inline int stop_machine(cpu_stop_fn_t fn, void *data, const struct cpumask *cpus)
{
    kfunc_call(stop_machine, fn, data, cpus);
    // todo:
    // unsigned long flags;
    // int ret;
    // local_irq_save(flags);
    // ret = fn(data);
    // local_irq_restore(flags);
    // return ret;
    kfunc_not_found();
    return 0;
}

#endif