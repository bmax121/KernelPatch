#ifndef _LINUX_SLAB_H
#define _LINUX_SLAB_H

#include <ktypes.h>
#include <ksyms.h>

// todo

struct kmem_cache;

void *__must_check kfunc_def(krealloc)(const void *, size_t, gfp_t);
void kfree(const void *);
void kfree_sensitive(const void *);
size_t __ksize(const void *);
size_t ksize(const void *);

extern void *kfunc_def(__kmalloc)(size_t size, gfp_t flags);
void *kmem_cache_alloc(struct kmem_cache *, gfp_t flags);
void kmem_cache_free(struct kmem_cache *, void *);

void kmem_cache_free_bulk(struct kmem_cache *, size_t, void **);
int kmem_cache_alloc_bulk(struct kmem_cache *, gfp_t, size_t, void **);

static inline void *kmalloc(size_t size, gfp_t flags)
{
    // todo
    kfunc_call(__kmalloc, size, flags);
    kfunc_not_found();
    return 0;
}

static inline void *kcalloc(size_t n, size_t size, gfp_t flags)
{
    return kmalloc(n * size, flags | __GFP_ZERO);
}

#endif