#ifndef _LINUX_SLAB_H
#define _LINUX_SLAB_H

#include <ktypes.h>
#include <pgtable.h>
#include <linux/gfp.h>
#include <ksyms.h>

// todo
struct kmem_cache;
struct list_lru;

extern void *kfunc_def(__kmalloc)(size_t size, gfp_t flags);
extern void *kfunc_def(kmalloc)(size_t size, gfp_t flags);
extern void kfunc_def(kfree)(const void *);
extern void kfunc_def(kvfree)(const void *addr);

void *__must_check krealloc(const void *, size_t, gfp_t);
void kfree_sensitive(const void *);
void kvfree_sensitive(const void *addr, size_t len);
size_t __ksize(const void *);
size_t ksize(const void *);
void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags);
void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru, gfp_t gfpflags);
void kmem_cache_free(struct kmem_cache *s, void *objp);
void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p);
int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size, void **p);

void *__kmalloc_node(size_t size, gfp_t flags, int node);
void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node);
void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size);
void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags, int node, size_t size);
void *kmalloc_large(size_t size, gfp_t flags);
void *kmalloc_large_node(size_t size, gfp_t flags, int node);

// todo: kernel version specified different gfp_t
static inline void *kmalloc(size_t size, gfp_t flags)
{
    kfunc_call(kmalloc, size, flags);
    kfunc_direct_call(__kmalloc, size, flags);
}

static inline void kfree(const void *objp)
{
    kfunc_direct_call(kfree, objp);
}

static inline void kvfree(const void *addr)
{
    kfunc_direct_call(kvfree, addr);
}

#endif