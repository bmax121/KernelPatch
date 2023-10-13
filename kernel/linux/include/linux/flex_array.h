/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FLEX_ARRAY_H
#define _FLEX_ARRAY_H

#include <ktypes.h>
#include <ksyms.h>

#include <linux/gfp.h>

struct flex_array;

extern struct flex_array *kfunc_def(flex_array_alloc)(int element_size, unsigned int total, gfp_t flags);
extern int kfunc_def(flex_array_prealloc)(struct flex_array *fa, unsigned int start, unsigned int nr_elements,
                                          gfp_t flags);
extern void kfunc_def(flex_array_free)(struct flex_array *fa);
extern void kfunc_def(flex_array_free_parts)(struct flex_array *fa);
extern int kfunc_def(flex_array_put)(struct flex_array *fa, unsigned int element_nr, void *src, gfp_t flags);
extern int kfunc_def(flex_array_clear)(struct flex_array *fa, unsigned int element_nr);
extern void *kfunc_def(flex_array_get)(struct flex_array *fa, unsigned int element_nr);
extern int kfunc_def(flex_array_shrink)(struct flex_array *fa);
extern void *kfunc_def(flex_array_get_ptr)(struct flex_array *fa, unsigned int element_nr);

#define flex_array_put_ptr(fa, nr, src, gfp) flex_array_put(fa, nr, (void *)&(src), gfp)

static inline struct flex_array *flex_array_alloc(int element_size, unsigned int total, gfp_t flags)
{
    kfunc_call(flex_array_alloc, element_size, total, flags);
    kfunc_not_found();
    return 0;
}
static inline int flex_array_prealloc(struct flex_array *fa, unsigned int start, unsigned int nr_elements, gfp_t flags)
{
    kfunc_call(flex_array_prealloc, fa, start, nr_elements, flags);
    kfunc_not_found();
    return 0;
}
static inline void flex_array_free(struct flex_array *fa)
{
    kfunc_call_void(flex_array_free, fa);
    kfunc_not_found();
}
static inline void flex_array_free_parts(struct flex_array *fa)
{
    kfunc_call_void(flex_array_free_parts, fa);
    kfunc_not_found();
}
static inline int flex_array_put(struct flex_array *fa, unsigned int element_nr, void *src, gfp_t flags)
{
    kfunc_call(flex_array_put, fa, element_nr, src, flags);
    kfunc_not_found();
    return 0;
}
static inline int flex_array_clear(struct flex_array *fa, unsigned int element_nr)
{
    kfunc_call(flex_array_clear, fa, element_nr);
    kfunc_not_found();
    return 0;
}
static inline void *flex_array_get(struct flex_array *fa, unsigned int element_nr)
{
    kfunc_call(flex_array_get, fa, element_nr);
    kfunc_not_found();
    return 0;
}
static inline int flex_array_shrink(struct flex_array *fa)
{
    kfunc_call(flex_array_shrink, fa);
    kfunc_not_found();
    return 0;
}
static inline void *flex_array_get_ptr(struct flex_array *fa, unsigned int element_nr)
{
    kfunc_call(flex_array_get_ptr, fa, element_nr);
    kfunc_not_found();
    return 0;
}

#endif