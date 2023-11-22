#ifndef _KP_CACHE_H_
#define _KP_CACHE_H_

#include <stdint.h>

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

/*
 * These definitions mirror those in pci.h, so they can be used
 * interchangeably with their PCI_ counterparts.
 */
enum dma_data_direction
{
    DMA_BIDIRECTIONAL = 0,
    DMA_TO_DEVICE = 1,
    DMA_FROM_DEVICE = 2,
    DMA_NONE = 3,
};

void flush_cache_all(void);
void flush_icache_range(unsigned long start, unsigned long end);
void __flush_dcache_all();
void __flush_dcache_area(void *addr, size_t len);
void __flush_cache_user_range(unsigned long start, unsigned long end);
void __inval_cache_range(unsigned long start, unsigned long end);
void __dma_inv_range(unsigned long start, unsigned long end);
void __dma_clean_range(unsigned long start, unsigned long end);
void __dma_flush_range(unsigned long start, unsigned long end);
void __dma_map_area(unsigned long start, unsigned long size, enum dma_data_direction dir);
void __dma_unmap_area(unsigned long start, unsigned long size, enum dma_data_direction dir);

#endif