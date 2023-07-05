#ifndef __ASM_THREAD_INFO_H
#define __ASM_THREAD_INFO_H

#include <stdint.h>

struct task_struct;
typedef unsigned long mm_segment_t;

struct thread_info
{
    unsigned long flags; /* low level flags */
    mm_segment_t addr_limit; /* address limit */
    // from 3.7 to 4.9
    struct task_struct *task; /* main task structure */
    char _others[0];
};

/*
 * low level task data that entry.S needs immediate access to.
 */
// struct thread_info {
// 	unsigned long flags; /* low level flags */
// 	mm_segment_t addr_limit; /* address limit */
// #ifdef CONFIG_ARM64_SW_TTBR0_PAN
// 	u64 ttbr0; /* saved TTBR0_EL1 */
// #endif
// 	union {
// 		u64 preempt_count; /* 0 => preemptible, <0 => bug */
// 		struct {
// #ifdef CONFIG_CPU_BIG_ENDIAN
// 			u32 need_resched;
// 			u32 count;
// #else
// 			u32 count;
// 			u32 need_resched;
// #endif
// 		} preempt;
// 	};
// #ifdef CONFIG_SHADOW_CALL_STACK
// 	void *scs_base;
// 	void *scs_sp;
// #endif
// };

#endif