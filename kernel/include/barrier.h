#ifndef _KP_BARRIER_H_
#define _KP_BARRIER_H_

#define mb() asm volatile("dmb ish" ::: "memory")
#define wmb() asm volatile("dmb ishst" ::: "memory")
#define rmb() asm volatile("dmb ishld" ::: "memory")

/*
 * Kernel uses dmb variants on arm64 for smp_*() barriers. Pretty much the same
 * implementation as above mb()/wmb()/rmb(), though for the latter kernel uses
 * dsb. In any case, should above mb()/wmb()/rmb() change, make sure the below
 * smp_*() don't.
 */
#define smp_mb() asm volatile("dmb ish" ::: "memory")
#define smp_wmb() asm volatile("dmb ishst" ::: "memory")
#define smp_rmb() asm volatile("dmb ishld" ::: "memory")

#define smp_store_release(p, v)                                                         \
    do {                                                                                \
        union                                                                           \
        {                                                                               \
            typeof(*p) __val;                                                           \
            char __c[1];                                                                \
        } __u = { .__val = (v) };                                                       \
        compiletime_assert_atomic_type(*p);                                             \
                                                                                        \
        switch (sizeof(*p)) {                                                           \
        case 1:                                                                         \
            asm volatile("stlrb %w1, %0" : "=Q"(*p) : "r"(*(u8 *)__u.__c) : "memory");  \
            break;                                                                      \
        case 2:                                                                         \
            asm volatile("stlrh %w1, %0" : "=Q"(*p) : "r"(*(u16 *)__u.__c) : "memory"); \
            break;                                                                      \
        case 4:                                                                         \
            asm volatile("stlr %w1, %0" : "=Q"(*p) : "r"(*(u32 *)__u.__c) : "memory");  \
            break;                                                                      \
        case 8:                                                                         \
            asm volatile("stlr %1, %0" : "=Q"(*p) : "r"(*(u64 *)__u.__c) : "memory");   \
            break;                                                                      \
        default:                                                                        \
            /* Only to shut up gcc ... */                                               \
            mb();                                                                       \
            break;                                                                      \
        }                                                                               \
    } while (0)

#define smp_load_acquire(p)                                                             \
    ({                                                                                  \
        union                                                                           \
        {                                                                               \
            typeof(*p) __val;                                                           \
            char __c[1];                                                                \
        } __u = { .__c = { 0 } };                                                       \
        compiletime_assert_atomic_type(*p);                                             \
                                                                                        \
        switch (sizeof(*p)) {                                                           \
        case 1:                                                                         \
            asm volatile("ldarb %w0, %1" : "=r"(*(u8 *)__u.__c) : "Q"(*p) : "memory");  \
            break;                                                                      \
        case 2:                                                                         \
            asm volatile("ldarh %w0, %1" : "=r"(*(u16 *)__u.__c) : "Q"(*p) : "memory"); \
            break;                                                                      \
        case 4:                                                                         \
            asm volatile("ldar %w0, %1" : "=r"(*(u32 *)__u.__c) : "Q"(*p) : "memory");  \
            break;                                                                      \
        case 8:                                                                         \
            asm volatile("ldar %0, %1" : "=r"(*(u64 *)__u.__c) : "Q"(*p) : "memory");   \
            break;                                                                      \
        default:                                                                        \
            /* Only to shut up gcc ... */                                               \
            mb();                                                                       \
            break;                                                                      \
        }                                                                               \
        __u.__val;                                                                      \
    })

#endif