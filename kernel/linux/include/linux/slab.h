#ifndef _LINUX_SLAB_H
#define _LINUX_SLAB_H

#include <ktypes.h>

// todo

void *__must_check krealloc(const void *, size_t, gfp_t);
void kfree(const void *);
void kfree_sensitive(const void *);
size_t __ksize(const void *);
size_t ksize(const void *);

void *__kmalloc(size_t size, gfp_t flags);
void *kmem_cache_alloc(struct kmem_cache *, gfp_t flags);
void kmem_cache_free(struct kmem_cache *, void *);

void kmem_cache_free_bulk(struct kmem_cache *, size_t, void **);
int kmem_cache_alloc_bulk(struct kmem_cache *, gfp_t, size_t, void **);

#endif