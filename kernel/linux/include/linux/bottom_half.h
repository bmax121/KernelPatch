/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BH_H
#define _LINUX_BH_H

#include <stdbool.h>
#include <ksyms.h>
#include <compiler.h>
#include <linux/preempt.h>

extern void kfunc_def(__local_bh_disable_ip)(unsigned long ip, unsigned int cnt);
extern void kfunc_def(__local_bh_enable_ip)(unsigned long ip, unsigned int cnt);
extern void kfunc_def(_local_bh_enable)(void);
extern bool kfunc_def(local_bh_blocked)(void);

static inline void local_bh_disable(void)
{
    kfunc_call(__local_bh_disable_ip, _THIS_IP_, SOFTIRQ_DISABLE_OFFSET);
}

static inline void local_bh_enable_ip(unsigned long ip)
{
    kfunc_call(__local_bh_enable_ip, ip, SOFTIRQ_DISABLE_OFFSET);
}

static inline void local_bh_enable(void)
{
    kfunc_call(__local_bh_enable_ip, _THIS_IP_, SOFTIRQ_DISABLE_OFFSET);
}

static inline bool local_bh_blocked(void)
{
    kfunc_call(local_bh_blocked);
    return false;
}

#endif