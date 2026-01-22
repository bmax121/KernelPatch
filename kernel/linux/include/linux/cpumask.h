#ifndef __LINUX_CPUMASK_H
#define __LINUX_CPUMASK_H

#include <linux/bitmap.h>

typedef struct cpumask
{
    unsigned long bits[0];
} cpumask_t;

extern const struct cpumask *kvar(cpu_online_mask);
extern const struct cpumask *kvar(__cpu_online_mask);
#define cpu_online_mask (kvar(__cpu_online_mask) ? kvar(__cpu_online_mask) : kvar(cpu_online_mask))

/**
 * cpumask_bits - get the bits in a cpumask
 * @maskp: the struct cpumask *
 *
 * You should only assume nr_cpu_ids bits of this mask are valid.  This is
 * a macro so it's const-correct.
 */
#define cpumask_bits(maskp) ((maskp)->bits)

#define num_online_cpus() cpumask_weight(cpu_online_mask)
#define num_possible_cpus() cpumask_weight(cpu_possible_mask)
#define num_present_cpus() cpumask_weight(cpu_present_mask)
#define num_active_cpus() cpumask_weight(cpu_active_mask)
#define cpu_online(cpu) cpumask_test_cpu((cpu), cpu_online_mask)
#define cpu_possible(cpu) cpumask_test_cpu((cpu), cpu_possible_mask)
#define cpu_present(cpu) cpumask_test_cpu((cpu), cpu_present_mask)
#define cpu_active(cpu) cpumask_test_cpu((cpu), cpu_active_mask)

extern const unsigned int kvar_def(nr_cpu_ids);
#define nr_cpumask_bits kvar_val(nr_cpu_ids)

/**
 * cpumask_weight - Count of bits in *srcp
 * @srcp: the cpumask to count bits (< nr_cpu_ids) in.
 */
static inline unsigned int cpumask_weight(const struct cpumask *srcp)
{
    return __bitmap_weight(cpumask_bits(srcp), nr_cpumask_bits);
}

#endif