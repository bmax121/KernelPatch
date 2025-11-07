#ifndef _LINUX_VMALLOC_H
#define _LINUX_VMALLOC_H

#include <ktypes.h>
#include <ksyms.h>
#include <compiler.h>
#include <common.h>

typedef size_t pgprot_t;

struct vm_area_struct; /* vma defining user mapping in mm_types.h */
struct notifier_block; /* in notifier.h */

/* bits in flags of vmalloc's vm_struct below */
#define VM_IOREMAP 0x00000001 /* ioremap() and friends */
#define VM_ALLOC 0x00000002 /* vmalloc() */
#define VM_MAP 0x00000004 /* vmap()ed pages */
#define VM_USERMAP 0x00000008 /* suitable for remap_vmalloc_range */
#define VM_DMA_COHERENT 0x00000010 /* dma_alloc_coherent */
#define VM_UNINITIALIZED 0x00000020 /* vm_struct is not fully initialized */
#define VM_NO_GUARD 0x00000040 /* don't add guard page */
#define VM_KASAN 0x00000080 /* has allocated kasan shadow memory */
#define VM_FLUSH_RESET_PERMS 0x00000100 /* reset direct map and flush TLB on unmap, can't be freed in atomic context */
#define VM_MAP_PUT_PAGES 0x00000200 /* put pages and free array in vfree */

struct vm_struct
{
    struct vm_struct *next;
    void *addr;
    unsigned long size;
    unsigned long flags;
    struct page **pages;
#ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC
    unsigned int page_order;
#endif
    unsigned int nr_pages;
    phys_addr_t phys_addr;
    const void *caller;
};

// struct vmap_area {
//     unsigned long va_start;
//     unsigned long va_end;

//     struct rb_node rb_node; /* address sorted rbtree */
//     struct list_head list; /* address sorted list */

//     /*
// 	 * The following three variables can be packed, because
// 	 * a vmap_area object is always one of the three states:
// 	 *    1) in "free" tree (root is vmap_area_root)
// 	 *    2) in "busy" tree (root is free_vmap_area_root)
// 	 *    3) in purge list  (head is vmap_purge_list)
// 	 */
//     union {
//         unsigned long subtree_max_size; /* in "free" tree */
//         struct vm_struct *vm; /* in "busy" tree */
//         struct llist_node purge_list; /* in purge list */
//     };
// };

extern void kfunc_def(vm_unmap_ram)(const void *mem, unsigned int count);
extern void *kfunc_def(vm_map_ram)(struct page **pages, unsigned int count, int node);
extern void kfunc_def(vm_unmap_aliases)(void);

extern void *kfunc_def(vmalloc)(unsigned long size);
extern void *kfunc_def(vzalloc)(unsigned long size);
extern void *kfunc_def(vmalloc_user)(unsigned long size);
extern void *kfunc_def(vmalloc_node)(unsigned long size, int node);
extern void *kfunc_def(vzalloc_node)(unsigned long size, int node);
extern void *kfunc_def(vmalloc_32)(unsigned long size);
extern void *kfunc_def(vmalloc_32_user)(unsigned long size);
extern void *kfunc_def(__vmalloc)(unsigned long size, gfp_t gfp_mask);

extern void *kfunc_def(__vmalloc_node_range)(unsigned long size, unsigned long align, unsigned long start,
                                             unsigned long end, gfp_t gfp_mask, pgprot_t prot, unsigned long vm_flags,
                                             int node, const void *caller);

extern void *kfunc_def(__vmalloc_node)(unsigned long size, unsigned long align, gfp_t gfp_mask, int node,
                                       const void *caller);

extern void kfunc_def(vfree)(const void *addr);
extern void kfunc_def(vfree_atomic)(const void *addr);

extern void *kfunc_def(vmap)(struct page **pages, unsigned int count, unsigned long flags, pgprot_t prot);
extern void *kfunc_def(vmap_pfn)(unsigned long *pfns, unsigned int count, pgprot_t prot);
extern void kfunc_def(vunmap)(const void *addr);
extern int kfunc_def(remap_vmalloc_range_partial)(struct vm_area_struct *vma, unsigned long uaddr, void *kaddr,
                                                  unsigned long pgoff, unsigned long size);
extern int kfunc_def(remap_vmalloc_range)(struct vm_area_struct *vma, void *addr, unsigned long pgoff);

extern struct vm_struct *kfunc_def(get_vm_area)(unsigned long size, unsigned long flags);
extern struct vm_struct *kfunc_def(get_vm_area_caller)(unsigned long size, unsigned long flags, const void *caller);
extern struct vm_struct *kfunc_def(__get_vm_area_caller)(unsigned long size, unsigned long flags, unsigned long start,
                                                         unsigned long end, const void *caller);
extern void kfunc_def(free_vm_area)(struct vm_struct *area);
extern struct vm_struct *kfunc_def(remove_vm_area)(const void *addr);
extern struct vm_struct *kfunc_def(find_vm_area)(const void *addr);

/* for /dev/kmem */
extern long kfunc_def(vread)(char *buf, char *addr, unsigned long count);
extern long kfunc_def(vwrite)(char *buf, char *addr, unsigned long count);

static inline void vm_unmap_ram(const void *mem, unsigned int count)
{
    kfunc_call(vm_unmap_ram, mem, count);
    kfunc_not_found();
}
static inline void *vm_map_ram(struct page **pages, unsigned int count, int node)
{
    kfunc_call(vm_map_ram, pages, count, node);
    kfunc_not_found();
    return 0;
}
static inline void vm_unmap_aliases(void)
{
    kfunc_call(vm_unmap_aliases);
    kfunc_not_found();
}

static inline void *vmalloc(unsigned long size)
{
    kfunc_call(vmalloc, size);
    kfunc_not_found();
    return 0;
}
static inline void *vzalloc(unsigned long size)
{
    kfunc_call(vzalloc, size);
    kfunc_not_found();
    return 0;
}
static inline void *vmalloc_user(unsigned long size)
{
    kfunc_call(vmalloc_user, size);
    kfunc_not_found();
    return 0;
}
static inline void *vmalloc_node(unsigned long size, int node)
{
    kfunc_call(vmalloc_node, size, node);
    kfunc_not_found();
    return 0;
}
static inline void *vzalloc_node(unsigned long size, int node)
{
    kfunc_call(vzalloc_node, size, node);
    kfunc_not_found();
    return 0;
}
static inline void *vmalloc_32(unsigned long size)
{
    kfunc_call(vmalloc_32, size);
    kfunc_not_found();
    return 0;
}
static inline void *vmalloc_32_user(unsigned long size)
{
    kfunc_call(vmalloc_32_user, size);
    kfunc_not_found();
    return 0;
}

static inline void *__vmalloc(unsigned long size, gfp_t gfp_mask)
{
    kfunc_call(__vmalloc, size, gfp_mask);
    kfunc_not_found();
    return 0;
}

static inline void *__vmalloc_node_range(unsigned long size, unsigned long align, unsigned long start,
                                         unsigned long end, gfp_t gfp_mask, pgprot_t prot, unsigned long vm_flags,
                                         int node, const void *caller)
{
    if (likely(kver >= VERSION(4, 0, 0))) {
        kfunc_call(__vmalloc_node_range, size, align, start, end, gfp_mask, prot, vm_flags, node, caller);
    } else {
        void *(*__vmalloc_node_range_legacy)(unsigned long size, unsigned long align, unsigned long start,
                                             unsigned long end, gfp_t gfp_mask, pgprot_t prot, int node,
                                             const void *caller) =
            (typeof(__vmalloc_node_range_legacy))kfunc(__vmalloc_node_range);
        if (__vmalloc_node_range_legacy)
            return __vmalloc_node_range_legacy(size, align, start, end, gfp_mask, prot, node, caller);
    }

    kfunc_not_found();
    return 0;
}

static inline void *__vmalloc_node(unsigned long size, unsigned long align, gfp_t gfp_mask, int node,
                                   const void *caller)

{
    kfunc_call(__vmalloc_node, size, align, gfp_mask, node, caller);
    kfunc_not_found();
    return 0;
}

static inline void vfree(const void *addr)
{
    kfunc_call(vfree, addr);
    kfunc_not_found();
}

static inline void vfree_atomic(const void *addr)
{
    kfunc_call(vfree_atomic, addr);
    kfunc_not_found();
}

static inline void *vmap(struct page **pages, unsigned int count, unsigned long flags, pgprot_t prot)
{
    kfunc_call(vmap, pages, count, flags, prot);
    kfunc_not_found();
    return 0;
}
static inline void *vmap_pfn(unsigned long *pfns, unsigned int count, pgprot_t prot)
{
    kfunc_call(vmap_pfn, pfns, count, prot);
    kfunc_not_found();
    return 0;
}
static inline void vunmap(const void *addr)
{
    kfunc_call(vunmap, addr);
    kfunc_not_found();
}
static inline int remap_vmalloc_range_partial(struct vm_area_struct *vma, unsigned long uaddr, void *kaddr,
                                              unsigned long pgoff, unsigned long size)
{
    kfunc_call(remap_vmalloc_range_partial, vma, uaddr, kaddr, pgoff, size);
    kfunc_not_found();
    return 0;
}
static inline int remap_vmalloc_range(struct vm_area_struct *vma, void *addr, unsigned long pgoff)
{
    kfunc_call(remap_vmalloc_range, vma, addr, pgoff);
    kfunc_not_found();
    return 0;
}

static inline struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
    kfunc_call(get_vm_area, size, flags);
    kfunc_not_found();
    return 0;
}
static inline struct vm_struct *get_vm_area_caller(unsigned long size, unsigned long flags, const void *caller)
{
    kfunc_call(get_vm_area_caller, size, flags, caller);
    kfunc_not_found();
    return 0;
}
static inline struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags, unsigned long start,
                                                     unsigned long end, const void *caller)
{
    kfunc_call(__get_vm_area_caller, size, flags, start, end, caller);
    kfunc_not_found();
    return 0;
}
static inline void free_vm_area(struct vm_struct *area)
{
    kfunc_call(free_vm_area, area);
    kfunc_not_found();
}
static inline struct vm_struct *remove_vm_area(const void *addr)
{
    kfunc_call(remove_vm_area, addr);
    kfunc_not_found();
    return 0;
}
static inline struct vm_struct *find_vm_area(const void *addr)
{
    kfunc_call(find_vm_area, addr);
    kfunc_not_found();
    return 0;
}

/* for /dev/kmem */
static inline long vread(char *buf, char *addr, unsigned long count)
{
    kfunc_call(vread, buf, addr, count);
    kfunc_not_found();
    return 0;
}
static inline long vwrite(char *buf, char *addr, unsigned long count)
{
    kfunc_call(vwrite, buf, addr, count);
    kfunc_not_found();
    return 0;
}

#endif