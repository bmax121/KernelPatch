#ifndef _LINUX_BITOPS_H
#define _LINUX_BITOPS_H

#include <ktypes.h>
#include <asm-generic/bitops/fls_ffs.h>

#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define DIV_ROUND_UP_ULL(ll, d)                 \
    ({                                          \
        unsigned long long _tmp = (ll) + (d)-1; \
        do_div(_tmp, d);                        \
        _tmp;                                   \
    })

#define BIT(nr) (1UL << (nr))
#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE 8
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

static inline void set_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
    unsigned long flags;
    *p |= mask;
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
    unsigned long flags;
    *p &= ~mask;
}

static inline unsigned int __sw_hweight8(unsigned int w)
{
    unsigned int res = w - ((w >> 1) & 0x55);
    res = (res & 0x33) + ((res >> 2) & 0x33);
    return (res + (res >> 4)) & 0x0F;
}

static inline unsigned int __sw_hweight16(unsigned int w)
{
    unsigned int res = w - ((w >> 1) & 0x5555);
    res = (res & 0x3333) + ((res >> 2) & 0x3333);
    res = (res + (res >> 4)) & 0x0F0F;
    return (res + (res >> 8)) & 0x00FF;
}

static inline unsigned int __sw_hweight32(unsigned int w)
{
    unsigned int res = w - ((w >> 1) & 0x55555555);
    res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
    res = (res + (res >> 4)) & 0x0F0F0F0F;
    res = res + (res >> 8);
    return (res + (res >> 16)) & 0x000000FF;
}

static inline unsigned long __sw_hweight64(__u64 w)
{
    __u64 res = w - ((w >> 1) & 0x5555555555555555ul);
    res = (res & 0x3333333333333333ul) + ((res >> 2) & 0x3333333333333333ul);
    res = (res + (res >> 4)) & 0x0F0F0F0F0F0F0F0Ful;
    res = res + (res >> 8);
    res = res + (res >> 16);
    return (res + (res >> 32)) & 0x00000000000000FFul;
}

static inline unsigned int __arch_hweight32(unsigned int w)
{
    return __sw_hweight32(w);
}

static inline unsigned int __arch_hweight16(unsigned int w)
{
    return __sw_hweight16(w);
}

static inline unsigned int __arch_hweight8(unsigned int w)
{
    return __sw_hweight8(w);
}

static inline unsigned long __arch_hweight64(__u64 w)
{
    return __sw_hweight64(w);
}

/*
 * Compile time versions of __arch_hweightN()
 */
#define __const_hweight8(w)                                                                       \
    ((unsigned int)((!!((w) & (1ULL << 0))) + (!!((w) & (1ULL << 1))) + (!!((w) & (1ULL << 2))) + \
                    (!!((w) & (1ULL << 3))) + (!!((w) & (1ULL << 4))) + (!!((w) & (1ULL << 5))) + \
                    (!!((w) & (1ULL << 6))) + (!!((w) & (1ULL << 7)))))

#define __const_hweight16(w) (__const_hweight8(w) + __const_hweight8((w) >> 8))
#define __const_hweight32(w) (__const_hweight16(w) + __const_hweight16((w) >> 16))
#define __const_hweight64(w) (__const_hweight32(w) + __const_hweight32((w) >> 32))

/*
 * Generic interface.
 */
#define hweight8(w) (__builtin_constant_p(w) ? __const_hweight8(w) : __arch_hweight8(w))
#define hweight16(w) (__builtin_constant_p(w) ? __const_hweight16(w) : __arch_hweight16(w))
#define hweight32(w) (__builtin_constant_p(w) ? __const_hweight32(w) : __arch_hweight32(w))
#define hweight64(w) (__builtin_constant_p(w) ? __const_hweight64(w) : __arch_hweight64(w))

/*
 * Interface for known constant arguments
 */
#define HWEIGHT8(w) (BUILD_BUG_ON_ZERO(!__builtin_constant_p(w)) + __const_hweight8(w))
#define HWEIGHT16(w) (BUILD_BUG_ON_ZERO(!__builtin_constant_p(w)) + __const_hweight16(w))
#define HWEIGHT32(w) (BUILD_BUG_ON_ZERO(!__builtin_constant_p(w)) + __const_hweight32(w))
#define HWEIGHT64(w) (BUILD_BUG_ON_ZERO(!__builtin_constant_p(w)) + __const_hweight64(w))

/*
 * Type invariant interface to the compile time constant hweight functions.
 */
#define HWEIGHT(w) HWEIGHT64((u64)w)

#define aligned_byte_mask(n) ((1UL << 8 * (n)) - 1)

#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_TYPE(long))
#define BITS_TO_U64(nr) DIV_ROUND_UP(nr, BITS_PER_TYPE(u64))
#define BITS_TO_U32(nr) DIV_ROUND_UP(nr, BITS_PER_TYPE(u32))
#define BITS_TO_BYTES(nr) DIV_ROUND_UP(nr, BITS_PER_TYPE(char))

#define for_each_set_bit(bit, addr, size) \
    for ((bit) = find_first_bit((addr), (size)); (bit) < (size); (bit) = find_next_bit((addr), (size), (bit) + 1))

/* same as for_each_set_bit() but use bit as value to start with */
#define for_each_set_bit_from(bit, addr, size) \
    for ((bit) = find_next_bit((addr), (size), (bit)); (bit) < (size); (bit) = find_next_bit((addr), (size), (bit) + 1))

#define for_each_clear_bit(bit, addr, size)                           \
    for ((bit) = find_first_zero_bit((addr), (size)); (bit) < (size); \
         (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

/* same as for_each_clear_bit() but use bit as value to start with */
#define for_each_clear_bit_from(bit, addr, size)                            \
    for ((bit) = find_next_zero_bit((addr), (size), (bit)); (bit) < (size); \
         (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

/**
 * for_each_set_clump8 - iterate over bitmap for each 8-bit clump with set bits
 * @start: bit offset to start search and to store the current iteration offset
 * @clump: location to store copy of current 8-bit clump
 * @bits: bitmap address to base the search on
 * @size: bitmap size in number of bits
 */
#define for_each_set_clump8(start, clump, bits, size)                             \
    for ((start) = find_first_clump8(&(clump), (bits), (size)); (start) < (size); \
         (start) = find_next_clump8(&(clump), (bits), (size), (start) + 8))

static inline int get_bitmask_order(unsigned int count)
{
    int order;

    order = fls(count);
    return order; /* We could be slightly more clever with -1 here... */
}

static __always_inline unsigned long hweight_long(unsigned long w)
{
    return sizeof(w) == 4 ? hweight32(w) : hweight64((__u64)w);
}

/**
 * rol64 - rotate a 64-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u64 rol64(__u64 word, unsigned int shift)
{
    return (word << (shift & 63)) | (word >> ((-shift) & 63));
}

/**
 * ror64 - rotate a 64-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u64 ror64(__u64 word, unsigned int shift)
{
    return (word >> (shift & 63)) | (word << ((-shift) & 63));
}

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

/**
 * ror32 - rotate a 32-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 ror32(__u32 word, unsigned int shift)
{
    return (word >> (shift & 31)) | (word << ((-shift) & 31));
}

/**
 * rol16 - rotate a 16-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u16 rol16(__u16 word, unsigned int shift)
{
    return (word << (shift & 15)) | (word >> ((-shift) & 15));
}

/**
 * ror16 - rotate a 16-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u16 ror16(__u16 word, unsigned int shift)
{
    return (word >> (shift & 15)) | (word << ((-shift) & 15));
}

/**
 * rol8 - rotate an 8-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u8 rol8(__u8 word, unsigned int shift)
{
    return (word << (shift & 7)) | (word >> ((-shift) & 7));
}

/**
 * ror8 - rotate an 8-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u8 ror8(__u8 word, unsigned int shift)
{
    return (word >> (shift & 7)) | (word << ((-shift) & 7));
}

/**
 * sign_extend32 - sign extend a 32-bit value using specified bit as sign-bit
 * @value: value to sign extend
 * @index: 0 based bit index (0<=index<32) to sign bit
 *
 * This is safe to use for 16- and 8-bit types as well.
 */
static __always_inline __s32 sign_extend32(__u32 value, int index)
{
    __u8 shift = 31 - index;
    return (__s32)(value << shift) >> shift;
}

/**
 * sign_extend64 - sign extend a 64-bit value using specified bit as sign-bit
 * @value: value to sign extend
 * @index: 0 based bit index (0<=index<64) to sign bit
 */
static __always_inline __s64 sign_extend64(__u64 value, int index)
{
    __u8 shift = 63 - index;
    return (__s64)(value << shift) >> shift;
}

static inline unsigned fls_long(unsigned long l)
{
    if (sizeof(l) == 4) return fls(l);
    return fls64(l);
}

static inline int get_count_order(unsigned int count)
{
    if (count == 0) return -1;

    return fls(--count);
}

/**
 * get_count_order_long - get order after rounding @l up to power of 2
 * @l: parameter
 *
 * it is same as get_count_order() but with long type parameter
 */
static inline int get_count_order_long(unsigned long l)
{
    if (l == 0UL) return -1;
    return (int)fls_long(--l);
}

/**
 * __ffs64 - find first set bit in a 64 bit word
 * @word: The 64 bit word
 *
 * On 64 bit arches this is a synomyn for __ffs
 * The result is not defined if no bits are set, so check that @word
 * is non-zero before calling this.
 */
static inline unsigned long __ffs64(u64 word)
{
    return __ffs((unsigned long)word);
}

/**
 * assign_bit - Assign value to a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 * @value: the value to assign
 */
static __always_inline void assign_bit(long nr, volatile unsigned long *addr, bool value)
{
    if (value)
        set_bit(nr, addr);
    else
        clear_bit(nr, addr);
}

static __always_inline void __assign_bit(long nr, volatile unsigned long *addr, bool value)
{
    if (value)
        __set_bit(nr, addr);
    else
        __clear_bit(nr, addr);
}

#define set_mask_bits(ptr, mask, bits)                         \
    ({                                                         \
        const typeof(*(ptr)) mask__ = (mask), bits__ = (bits); \
        typeof(*(ptr)) old__, new__;                           \
                                                               \
        do {                                                   \
            old__ = READ_ONCE(*(ptr));                         \
            new__ = (old__ & ~mask__) | bits__;                \
        } while (cmpxchg(ptr, old__, new__) != old__);         \
                                                               \
        old__;                                                 \
    })

#define bit_clear_unless(ptr, clear, test)                                  \
    ({                                                                      \
        const typeof(*(ptr)) clear__ = (clear), test__ = (test);            \
        typeof(*(ptr)) old__, new__;                                        \
                                                                            \
        do {                                                                \
            old__ = READ_ONCE(*(ptr));                                      \
            new__ = old__ & ~clear__;                                       \
        } while (!(old__ & test__) && cmpxchg(ptr, old__, new__) != old__); \
                                                                            \
        !(old__ & test__);                                                  \
    })

#endif