#ifndef _LINUX_STOP_MACHINE
#define _LINUX_STOP_MACHINE

#include <ktypes.h>
#include <ksyms.h>

typedef int (*cpu_stop_fn_t)(void *arg);

struct cpumask;

extern int kfunc_def(stop_machine)(int (*fn)(void *), void *data, const struct cpumask *cpus);

#endif