#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H

#include <compiler.h>
#include <ktypes.h>

#define MAX_ERRNO 4095

#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void *__must_check ERR_PTR(long error)
{
    return (void *)error;
}

static inline long __must_check PTR_ERR(__force const void *ptr)
{
    return (long)ptr;
}

static inline int __must_check IS_ERR(__force const void *ptr)
{
    return IS_ERR_VALUE((unsigned long)ptr);
}

static inline int __must_check PTR_ERR_OR_ZERO(__force const void *ptr)
{
    if (IS_ERR(ptr))
        return PTR_ERR(ptr);
    else
        return 0;
}

#endif