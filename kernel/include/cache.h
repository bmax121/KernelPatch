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

/*
 * Utility macro to choose an instruction according to the exception
 * level (EL) passed, which number is concatenated between insa and insb parts
 */
#define SWITCH_EL(insa, insb, el)    \
    if (el == 1)                     \
        asm volatile(insa "1" insb); \
    else if (el == 2)                \
        asm volatile(insa "2" insb); \
    else                             \
        asm volatile(insa "3" insb)
/* get current exception level (EL1-EL3) */
static inline uint32_t current_el(void)
{
    uint32_t el;
    asm volatile("mrs %w0, CurrentEL" : "=r"(el));
    return el >> 2;
}

/* write translation table base register 0 (TTBR0_ELx) */
static inline void write_ttbr0(uint64_t val, uint32_t el)
{
    SWITCH_EL("msr ttbr0_el", ", %0" : : "r"(val) : "memory", el);
}
/* read translation control register (TCR_ELx) */
static inline uint64_t read_tcr(uint32_t el)
{
    uint64_t val = 0;
    SWITCH_EL("mrs %0, tcr_el", : "=r"(val), el);
    return val;
}
/* write translation control register (TCR_ELx) */
static inline void write_tcr(uint64_t val, uint32_t el)
{
    SWITCH_EL("msr tcr_el", ", %0" : : "r"(val) : "memory", el);
}

/* data cache clean and invalidate by VA to PoC */
static inline void dccivac(uint64_t va)
{
    asm volatile("dc civac, %0" : : "r"(va) : "memory");
}
/* data cache clean and invalidate by set/way */
static inline void dccisw(uint64_t val)
{
    asm volatile("dc cisw, %0" : : "r"(val) : "memory");
}
/* data cache clean by VA to PoC */
static inline void dccvac(uint64_t va)
{
    asm volatile("dc cvac, %0" : : "r"(va) : "memory");
}
/* data cache clean by set/way */
static inline void dccsw(uint64_t val)
{
    asm volatile("dc csw, %0" : : "r"(val) : "memory");
}
/* data cache invalidate by VA to PoC */
static inline void dcivac(uint64_t va)
{
    asm volatile("dc ivac, %0" : : "r"(va) : "memory");
}
/* data cache invalidate by set/way */
static inline void dcisw(uint64_t val)
{
    asm volatile("dc isw, %0" : : "r"(val) : "memory");
}
/* instruction cache invalidate all */
static inline void iciallu(void)
{
    asm volatile("ic iallu" : : : "memory");
}

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
