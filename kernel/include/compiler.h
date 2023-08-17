#ifndef _KP_COMPILER_H_
#define _KP_COMPILER_H_

#define __pure __attribute__((pure))
#define __aligned(x) __attribute__((aligned(x)))
#define __printf(a, b) __attribute__((format(printf, a, b)))
#define __scanf(a, b) __attribute__((format(scanf, a, b)))
#define __attribute_const__ __attribute__((__const__))
#define __maybe_unused __attribute__((unused))
#define __always_unused __attribute__((unused))

#define __noreturn __attribute__((__noreturn__))
#define __noinline __attribute__((__noinline__))
#define __always_inline inline __attribute__((__always_inline__))
// #define __section(S) __attribute__((__section__(#S)))
#define __cold
#define __visible
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define __native_word(t) \
    (sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))

#define __user
#define __kernel
#define __safe __attribute__((safe))
// #define __force __attribute__((force))
#define __force
#define __nocast __attribute__((nocast))
#define __iomem
#define __chk_user_ptr(x) (void)0
#define __chk_io_ptr(x) (void)0
#define __builtin_warning(x, y...) (1)
#define __must_hold(x) __attribute__((context(x, 1, 1)))
#define __acquires(x) __attribute__((context(x, 0, 1)))
#define __releases(x) __attribute__((context(x, 1, 0)))
#define __acquire(x) __context__(x, 1)
#define __release(x) __context__(x, -1)
#define __cond_lock(x, c) \
    ((c) ? ({             \
        __acquire(x);     \
        1;                \
    }) :                  \
           0)
#define __percpu
#define __rcu
#define __pmem

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define __weak __attribute__((weak))
#define __packed __attribute__((__packed__))
#define __used __attribute__((__unused__))
#define __maybe_unused __attribute__((unused))

#endif