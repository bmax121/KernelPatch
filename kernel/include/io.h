#ifndef __KP_IO_H
#define __KP_IO_H

#include <ktypes.h>
#include <barrier.h>

// todo:
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)

#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)

/*
 * Generic IO read/write.  These perform native-endian accesses.
 */
static inline void __raw_writeb(u8 val, volatile void __iomem *addr)
{
    asm volatile("strb %w0, [%1]" : : "r"(val), "r"(addr));
}

static inline void __raw_writew(u16 val, volatile void __iomem *addr)
{
    asm volatile("strh %w0, [%1]" : : "r"(val), "r"(addr));
}

static inline void __raw_writel(u32 val, volatile void __iomem *addr)
{
    asm volatile("str %w0, [%1]" : : "r"(val), "r"(addr));
}

static inline void __raw_writeq(u64 val, volatile void __iomem *addr)
{
    asm volatile("str %0, [%1]" : : "r"(val), "r"(addr));
}

static inline u8 __raw_readb(const volatile void __iomem *addr)
{
    u8 val;
    asm volatile(
        // "ldrb %w0, [%1]"
        "ldarb %w0, [%1]"
        : "=r"(val)
        : "r"(addr));
    return val;
}

static inline u16 __raw_readw(const volatile void __iomem *addr)
{
    u16 val;

    asm volatile(
        // "ldrh %w0, [%1]"
        "ldarh %w0, [%1]"
        : "=r"(val)
        : "r"(addr));
    return val;
}

static inline u32 __raw_readl(const volatile void __iomem *addr)
{
    u32 val;
    asm volatile(
        // "ldr %w0, [%1]"
        "ldar %w0, [%1]"
        : "=r"(val)
        : "r"(addr));
    return val;
}

static inline u64 __raw_readq(const volatile void __iomem *addr)
{
    u64 val;
    asm volatile(
        // "ldr %0, [%1]"
        "ldar %0, [%1]"
        : "=r"(val)
        : "r"(addr));
    return val;
}

/* IO barriers */
#define __iormb() rmb()
#define __iowmb() wmb()

#define mmiowb() \
    do {         \
    } while (0)

/*
 * Relaxed I/O memory access primitives. These follow the Device memory
 * ordering rules but do not guarantee any ordering relative to Normal memory
 * accesses.
 */
#define readb_relaxed(c)         \
    ({                           \
        u8 __v = __raw_readb(c); \
        __v;                     \
    })
#define readw_relaxed(c)                                       \
    ({                                                         \
        u16 __v = le16_to_cpu((__force __le16)__raw_readw(c)); \
        __v;                                                   \
    })
#define readl_relaxed(c)                                       \
    ({                                                         \
        u32 __v = le32_to_cpu((__force __le32)__raw_readl(c)); \
        __v;                                                   \
    })
#define readq_relaxed(c)                                       \
    ({                                                         \
        u64 __v = le64_to_cpu((__force __le64)__raw_readq(c)); \
        __v;                                                   \
    })

#define writeb_relaxed(v, c) ((void)__raw_writeb((v), (c)))
#define writew_relaxed(v, c) ((void)__raw_writew((__force u16)cpu_to_le16(v), (c)))
#define writel_relaxed(v, c) ((void)__raw_writel((__force u32)cpu_to_le32(v), (c)))
#define writeq_relaxed(v, c) ((void)__raw_writeq((__force u64)cpu_to_le64(v), (c)))

/*
 * I/O memory access primitives. Reads are ordered relative to any
 * following Normal memory access. Writes are ordered relative to any prior
 * Normal memory access.
 */
#define readb(c)                   \
    ({                             \
        u8 __v = readb_relaxed(c); \
        __iormb();                 \
        __v;                       \
    })
#define readw(c)                    \
    ({                              \
        u16 __v = readw_relaxed(c); \
        __iormb();                  \
        __v;                        \
    })
#define readl(c)                    \
    ({                              \
        u32 __v = readl_relaxed(c); \
        __iormb();                  \
        __v;                        \
    })
#define readq(c)                    \
    ({                              \
        u64 __v = readq_relaxed(c); \
        __iormb();                  \
        __v;                        \
    })

#define writeb(v, c)              \
    ({                            \
        __iowmb();                \
        writeb_relaxed((v), (c)); \
    })
#define writew(v, c)              \
    ({                            \
        __iowmb();                \
        writew_relaxed((v), (c)); \
    })
#define writel(v, c)              \
    ({                            \
        __iowmb();                \
        writel_relaxed((v), (c)); \
    })
#define writeq(v, c)              \
    ({                            \
        __iowmb();                \
        writeq_relaxed((v), (c)); \
    })

#endif