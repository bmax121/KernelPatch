#ifndef _LINUX_THREAD_INFO_H
#define _LINUX_THREAD_INFO_H

#include <asm/current.h>
#include <asm/thread_info.h>

// CONFIG_THREAD_INFO_IN_TASK
#define current_thread_info() ((struct thread_info *)current)

// unsigned long sp;
// asm("mrs %0, sp" : "=r"(sp));
// #define THREAD_SIZE 16384
// return (struct thread_info *)(sp & ~(THREAD_SIZE - 1));

#endif