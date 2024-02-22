#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <ktypes.h>

struct address_space;
struct mem_cgroup;

struct page
{
};

/*
 * This struct describes a virtual memory area. There is one of these
 * per VM-area/task. A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct
{
    //     /* The first cache line has the info for VMA tree walking. */

    //     unsigned long vm_start; /* Our start address within vm_mm. */
    //     unsigned long vm_end; /* The first byte after our end address
    // 					   within vm_mm. */

    //     struct mm_struct *vm_mm; /* The address space we belong to. */

    //     /*
    // 	 * Access permissions of this VMA.
    // 	 * See vmf_insert_mixed_prot() for discussion.
    // 	 */
    //     pgprot_t vm_page_prot;
    //     unsigned long vm_flags; /* Flags, see mm.h. */

    //     /*
    // 	 * For areas with an address space and backing store,
    // 	 * linkage into the address_space->i_mmap interval tree.
    // 	 *
    // 	 * For private anonymous mappings, a pointer to a null terminated string
    // 	 * containing the name given to the vma, or NULL if unnamed.
    // 	 */

    //     union
    //     {
    //         struct
    //         {
    //             struct rb_node rb;
    //             unsigned long rb_subtree_last;
    //         } shared;
    //         /*
    // 		 * Serialized by mmap_sem. Never use directly because it is
    // 		 * valid only when vm_file is NULL. Use anon_vma_name instead.
    // 		 */
    //         struct anon_vma_name *anon_name;
    //     };

    //     /*
    // 	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
    // 	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
    // 	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
    // 	 * or brk vma (with NULL file) can only be in an anon_vma list.
    // 	 */
    //     struct list_head anon_vma_chain; /* Serialized by mmap_lock &
    // 					  * page_table_lock */
    //     struct anon_vma *anon_vma; /* Serialized by page_table_lock */

    //     /* Function pointers to deal with this struct. */
    //     const struct vm_operations_struct *vm_ops;

    //     /* Information about our backing store: */
    //     unsigned long vm_pgoff; /* Offset (within vm_file) in PAGE_SIZE
    // 					   units */
    //     struct file *vm_file; /* File we map to (can be NULL). */
    //     void *vm_private_data; /* was vm_pte (shared mem) */

    // #ifdef CONFIG_SWAP
    //     atomic_long_t swap_readahead_info;
    // #endif
    // #ifndef CONFIG_MMU
    //     struct vm_region *vm_region; /* NOMMU mapping region */
    // #endif
    // #ifdef CONFIG_NUMA
    //     struct mempolicy *vm_policy; /* NUMA policy for the VMA */
    // #endif
    //     struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
}; //__randomize_layout

struct mm_struct
{
    //     struct
    //     {
    //         struct maple_tree mm_mt;
    // #ifdef CONFIG_MMU
    //         unsigned long (*get_unmapped_area)(struct file *filp, unsigned long addr, unsigned long len,
    //                                            unsigned long pgoff, unsigned long flags);
    // #endif
    //         unsigned long mmap_base; /* base of mmap area */
    //         unsigned long mmap_legacy_base; /* base of mmap area in bottom-up allocations */
    // #ifdef CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES
    //         /* Base addresses for compatible mmap() */
    //         unsigned long mmap_compat_base;
    //         unsigned long mmap_compat_legacy_base;
    // #endif
    //         unsigned long task_size; /* size of task vm space */
    //         pgd_t *pgd;

    // #ifdef CONFIG_MEMBARRIER
    //         /**
    // 		 * @membarrier_state: Flags controlling membarrier behavior.
    // 		 *
    // 		 * This field is close to @pgd to hopefully fit in the same
    // 		 * cache-line, which needs to be touched by switch_mm().
    // 		 */
    //         atomic_t membarrier_state;
    // #endif

    //         /**
    // 		 * @mm_users: The number of users including userspace.
    // 		 *
    // 		 * Use mmget()/mmget_not_zero()/mmput() to modify. When this
    // 		 * drops to 0 (i.e. when the task exits and there are no other
    // 		 * temporary reference holders), we also release a reference on
    // 		 * @mm_count (which may then free the &struct mm_struct if
    // 		 * @mm_count also drops to 0).
    // 		 */
    //         atomic_t mm_users;

    //         /**
    // 		 * @mm_count: The number of references to &struct mm_struct
    // 		 * (@mm_users count as 1).
    // 		 *
    // 		 * Use mmgrab()/mmdrop() to modify. When this drops to 0, the
    // 		 * &struct mm_struct is freed.
    // 		 */
    //         atomic_t mm_count;

    // #ifdef CONFIG_MMU
    //         atomic_long_t pgtables_bytes; /* PTE page table pages */
    // #endif
    //         int map_count; /* number of VMAs */

    //         spinlock_t page_table_lock; /* Protects page tables and some
    // 					     * counters
    // 					     */
    //         /*
    // 		 * With some kernel config, the current mmap_lock's offset
    // 		 * inside 'mm_struct' is at 0x120, which is very optimal, as
    // 		 * its two hot fields 'count' and 'owner' sit in 2 different
    // 		 * cachelines,  and when mmap_lock is highly contended, both
    // 		 * of the 2 fields will be accessed frequently, current layout
    // 		 * will help to reduce cache bouncing.
    // 		 *
    // 		 * So please be careful with adding new fields before
    // 		 * mmap_lock, which can easily push the 2 fields into one
    // 		 * cacheline.
    // 		 */
    //         struct rw_semaphore mmap_lock;

    //         struct list_head mmlist; /* List of maybe swapped mm's.	These
    // 					  * are globally strung together off
    // 					  * init_mm.mmlist, and are protected
    // 					  * by mmlist_lock
    // 					  */

    //         unsigned long hiwater_rss; /* High-watermark of RSS usage */
    //         unsigned long hiwater_vm; /* High-water virtual memory usage */

    //         unsigned long total_vm; /* Total pages mapped */
    //         unsigned long locked_vm; /* Pages that have PG_mlocked set */
    //         atomic64_t pinned_vm; /* Refcount permanently increased */
    //         unsigned long data_vm; /* VM_WRITE & ~VM_SHARED & ~VM_STACK */
    //         unsigned long exec_vm; /* VM_EXEC & ~VM_WRITE & ~VM_STACK */
    //         unsigned long stack_vm; /* VM_STACK */
    //         unsigned long def_flags;

    //         /**
    // 		 * @write_protect_seq: Locked when any thread is write
    // 		 * protecting pages mapped by this mm to enforce a later COW,
    // 		 * for instance during page table copying for fork().
    // 		 */
    //         seqcount_t write_protect_seq;

    //         spinlock_t arg_lock; /* protect the below fields */

    //         unsigned long start_code, end_code, start_data, end_data;
    //         unsigned long start_brk, brk, start_stack;
    //         unsigned long arg_start, arg_end, env_start, env_end;

    //         unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

    //         /*
    // 		 * Special counters, in some configurations protected by the
    // 		 * page_table_lock, in other configurations by being atomic.
    // 		 */
    //         struct mm_rss_stat rss_stat;

    //         struct linux_binfmt *binfmt;

    //         /* Architecture-specific MM context */
    //         mm_context_t context;

    //         unsigned long flags; /* Must use atomic bitops to access */

    // #ifdef CONFIG_AIO
    //         spinlock_t ioctx_lock;
    //         struct kioctx_table __rcu *ioctx_table;
    // #endif
    // #ifdef CONFIG_MEMCG
    //         /*
    // 		 * "owner" points to a task that is regarded as the canonical
    // 		 * user/owner of this mm. All of the following must be true in
    // 		 * order for it to be changed:
    // 		 *
    // 		 * current == mm->owner
    // 		 * current->mm != mm
    // 		 * new_owner->mm == mm
    // 		 * new_owner->alloc_lock is held
    // 		 */
    //         struct task_struct __rcu *owner;
    // #endif
    //         struct user_namespace *user_ns;

    //         /* store ref to file /proc/<pid>/exe symlink points to */
    //         struct file __rcu *exe_file;
    // #ifdef CONFIG_MMU_NOTIFIER
    //         struct mmu_notifier_subscriptions *notifier_subscriptions;
    // #endif
    // #if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS
    //         pgtable_t pmd_huge_pte; /* protected by page_table_lock */
    // #endif
    // #ifdef CONFIG_NUMA_BALANCING
    //         /*
    // 		 * numa_next_scan is the next time that PTEs will be remapped
    // 		 * PROT_NONE to trigger NUMA hinting faults; such faults gather
    // 		 * statistics and migrate pages to new nodes if necessary.
    // 		 */
    //         unsigned long numa_next_scan;

    //         /* Restart point for scanning and remapping PTEs. */
    //         unsigned long numa_scan_offset;

    //         /* numa_scan_seq prevents two threads remapping PTEs. */
    //         int numa_scan_seq;
    // #endif
    //         /*
    // 		 * An operation with batched TLB flushing is going on. Anything
    // 		 * that can move process memory needs to flush the TLB when
    // 		 * moving a PROT_NONE mapped page.
    // 		 */
    //         atomic_t tlb_flush_pending;
    // #ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
    //         /* See flush_tlb_batched_pending() */
    //         atomic_t tlb_flush_batched;
    // #endif
    //         struct uprobes_state uprobes_state;
    // #ifdef CONFIG_PREEMPT_RT
    //         struct rcu_head delayed_drop;
    // #endif
    // #ifdef CONFIG_HUGETLB_PAGE
    //         atomic_long_t hugetlb_usage;
    // #endif
    //         struct work_struct async_put_work;

    // #ifdef CONFIG_IOMMU_SVA
    //         u32 pasid;
    // #endif
    // #ifdef CONFIG_KSM
    //         /*
    // 		 * Represent how many pages of this process are involved in KSM
    // 		 * merging.
    // 		 */
    //         unsigned long ksm_merging_pages;
    //         /*
    // 		 * Represent how many pages are checked for ksm merging
    // 		 * including merged and not merged.
    // 		 */
    //         unsigned long ksm_rmap_items;
    // #endif
    // #ifdef CONFIG_LRU_GEN
    //         struct
    //         {
    //             /* this mm_struct is on lru_gen_mm_list */
    //             struct list_head list;
    //             /*
    // 			 * Set when switching to this mm_struct, as a hint of
    // 			 * whether it has been used since the last time per-node
    // 			 * page table walkers cleared the corresponding bits.
    // 			 */
    //             unsigned long bitmap;
    // #ifdef CONFIG_MEMCG
    //             /* points to the memcg of "owner" above */
    //             struct mem_cgroup *memcg;
    // #endif
    //         } lru_gen;
    // #endif /* CONFIG_LRU_GEN */
    //     } __randomize_layout;

    //     /*
    // 	 * The mm_cpumask needs to be at the end of mm_struct, because it
    // 	 * is dynamically sized based on nr_cpu_ids.
    // 	 */
    //     unsigned long cpu_bitmap[];
};

struct mm_struct_offset
{
    int16_t mmap_base_offset;
    int16_t task_size_offset;
    int16_t pgd_offset;
    int16_t map_count_offset;
    int16_t total_vm_offset;
    int16_t locked_vm_offset;
    int16_t pinned_vm_offset;
    int16_t data_vm_offset;
    int16_t exec_vm_offset;
    int16_t stack_vm_offset;
    int16_t start_code_offset, end_code_offset, start_data_offset, end_data_offset;
    int16_t start_brk_offset, brk_offset, start_stack_offset;
    int16_t arg_start_offset, arg_end_offset, env_start_offset, env_end_offset;
};

extern struct mm_struct_offset mm_struct_offset;

#endif