#ifndef _KP_CACHE_H_
#define _KP_CACHE_H_

#include <stdint.h>

// todo: arch/arm64/mm/cache.S

static inline void local_flush_icache_all(void)
{
    asm volatile("ic iallu");
    asm volatile("dsb nsh" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static inline void flush_icache_all(void)
{
    asm volatile("dsb ish" : : : "memory");
    asm volatile("ic ialluis");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

// todo
void flush_dcache_area(uint64_t kaddr, uint64_t size);

#endif