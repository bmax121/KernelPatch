#ifndef _KP_KPMALLOC_H_
#define _KP_KPMALLOC_H_

#include <tlsf.h>

extern tlsf_t kp_rw_mem;
extern tlsf_t kp_rox_mem;

static inline void *kp_malloc_exec(size_t bytes)
{
    return tlsf_malloc(kp_rox_mem, bytes);
}

static inline void *kp_memalign_exec(size_t align, size_t bytes)
{
    return tlsf_memalign(kp_rox_mem, align, bytes);
}

static inline void *kp_realloc_exec(void *ptr, size_t size)
{
    return tlsf_realloc(kp_rox_mem, ptr, size);
}

static inline void kp_free_exec(void *ptr)
{
    tlsf_free(kp_rox_mem, ptr);
}

static inline void *kp_malloc(size_t bytes)
{
    return tlsf_malloc(kp_rw_mem, bytes);
}

static inline void *kp_memalign(size_t align, size_t bytes)
{
    return tlsf_memalign(kp_rw_mem, align, bytes);
}

static inline void *kp_realloc(void *ptr, size_t size)
{
    return tlsf_realloc(kp_rw_mem, ptr, size);
}

static inline void kp_free(void *ptr)
{
    tlsf_free(kp_rw_mem, ptr);
}

#endif