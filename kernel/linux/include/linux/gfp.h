#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

#include <common.h>

/* Plain integer GFP bitmasks. Do not use this directly. */
// #define __GFP_DMA 0x01u
// #define __GFP_HIGHMEM 0x02u
// #define __GFP_DMA32 0x04u
// #define __GFP_MOVABLE 0x08u
// #define __GFP_RECLAIMABLE 0x10u
// #define __GFP_HIGH 0x20u
// #define __GFP_IO 0x40u
// #define __GFP_FS 0x80u
// #define __GFP_ZERO 0x100u
// #define __GFP_ATOMIC 0x200u
// #define __GFP_DIRECT_RECLAIM 0x400u
// #define __GFP_KSWAPD_RECLAIM 0x800u
// #define __GFP_WRITE 0x1000u
// #define __GFP_NOWARN 0x2000u
// #define __GFP_RETRY_MAYFAIL 0x4000u
// #define __GFP_NOFAIL 0x8000u
// #define __GFP_NORETRY 0x10000u
// #define __GFP_MEMALLOC 0x20000u
// #define __GFP_COMP 0x40000u
// #define __GFP_NOMEMALLOC 0x80000u
// #define __GFP_HARDWALL 0x100000u
// #define __GFP_THISNODE 0x200000u
// #define __GFP_ACCOUNT 0x400000u
// #define __GFP_NOLOCKDEP 0x800000u

// static inline get_gfp_atomic()
// {
//     if (kver >= VERSION(3, 18, 0)) return __GFP_HIGH;

// }

// #define __GFP_RECLAIM ((__force gfp_t)(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM))

// #define GFP_ATOMIC (__GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM)
// #define GFP_KERNEL (__GFP_RECLAIM | __GFP_IO | __GFP_FS)

// #define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
// #define GFP_NOWAIT (__GFP_KSWAPD_RECLAIM)
// #define GFP_NOIO (__GFP_RECLAIM)
// #define GFP_NOFS (__GFP_RECLAIM | __GFP_IO)
// #define GFP_USER (__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
// #define GFP_DMA __GFP_DMA
// #define GFP_DMA32 __GFP_DMA32
// #define GFP_HIGHUSER (GFP_USER | __GFP_HIGHMEM)
// #define GFP_HIGHUSER_MOVABLE (GFP_HIGHUSER | __GFP_MOVABLE)
// #define GFP_TRANSHUGE_LIGHT ((GFP_HIGHUSER_MOVABLE | __GFP_COMP | __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
// #define GFP_TRANSHUGE (GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)

/* Convert GFP flags to their corresponding migrate type */
// #define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE | __GFP_MOVABLE)
// #define GFP_MOVABLE_SHIFT 3

#endif