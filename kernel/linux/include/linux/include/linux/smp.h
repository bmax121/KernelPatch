#ifndef __LINUX_SMP_H
#define __LINUX_SMP_H

typedef void (*smp_call_func_t)(void *info);

void kick_all_cpus_sync(void);
void wake_up_all_idle_cpus(void);

#endif