/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ksyms.h>
#include <ktypes.h>
#include <symbol.h>
#include <common.h>
#include <stdarg.h>

#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/sched/task.h>

#ifndef INIT_USE_KALLSYMS_LOOKUP_NAME
int _ksym_local_strcmp(const char *s1, const char *s2)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (1) {
        d = (int)(ch = *c1++) - (int)*c2++;
        if (d || !ch) break;
    }
    return d;
}
#endif

struct group_info *kfunc_def(groups_alloc)(int gidsetsize) = 0;
void kfunc_def(set_groups)(struct cred *, struct group_info *group_info) = 0;

void kfunc_def(__put_cred)(struct cred *) = 0;
void kfunc_def(exit_creds)(struct task_struct *) = 0;
int kfunc_def(copy_creds)(struct task_struct *, unsigned long) = 0;
const struct cred *kfunc_def(get_task_cred)(struct task_struct *) = 0;
struct cred *kfunc_def(cred_alloc_blank)(void) = 0;
struct cred *kfunc_def(prepare_creds)(void) = 0;
struct cred *kfunc_def(prepare_exec_creds)(void) = 0;
int kfunc_def(commit_creds)(struct cred *) = 0;
void kfunc_def(abort_creds)(struct cred *) = 0;
const struct cred *kfunc_def(override_creds)(const struct cred *) = 0;
void kfunc_def(revert_creds)(const struct cred *) = 0;
struct cred *kfunc_def(prepare_kernel_cred)(struct task_struct *) = 0;
int kfunc_def(change_create_files_as)(struct cred *, struct inode *) = 0;
int kfunc_def(set_security_override)(struct cred *, u32) = 0;
int kfunc_def(set_security_override_from_ctx)(struct cred *, const char *) = 0;
int kfunc_def(set_create_files_as)(struct cred *, struct inode *) = 0;
int kfunc_def(cred_fscmp)(const struct cred *, const struct cred *) = 0;
void kfunc_def(cred_init)(void) = 0;
bool kfunc_def(creds_are_invalid)(const struct cred *cred) = 0;

void _linux_kernel_cred_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(groups_alloc, name, addr);
    kfunc_match(set_groups, name, addr);

    kfunc_match(__put_cred, name, addr);
    // kfunc_match(exit_creds, name, addr);
    kfunc_match(copy_creds, name, addr);
    kfunc_match(get_task_cred, name, addr);
    kfunc_match(cred_alloc_blank, name, addr);
    kfunc_match(prepare_creds, name, addr);
    kfunc_match(prepare_exec_creds, name, addr);
    kfunc_match(commit_creds, name, addr);
    // kfunc_match(abort_creds, name, addr);
    kfunc_match(override_creds, name, addr);
    // kfunc_match(revert_creds, name, addr);
    kfunc_match(prepare_kernel_cred, name, addr);
    // kfunc_match(change_create_files_as, name, addr);
    kfunc_match(set_security_override, name, addr);
    kfunc_match(set_security_override_from_ctx, name, addr);
    // kfunc_match(set_create_files_as, name, addr);
    // kfunc_match(cred_fscmp, name, addr);
    // kfunc_match(cred_init, name, addr);
    // kfunc_match(creds_are_invalid, name, addr);
}

// kernel/locking/spinlock.c
#include <linux/spinlock.h>

int kfunc_def(_raw_spin_trylock)(raw_spinlock_t *lock) = 0;
int kfunc_def(_raw_spin_trylock_bh)(raw_spinlock_t *lock) = 0;
void kfunc_def(_raw_spin_lock)(raw_spinlock_t *lock) = 0;
unsigned long kfunc_def(_raw_spin_lock_irqsave)(raw_spinlock_t *lock) = 0;
void kfunc_def(_raw_spin_lock_irq)(raw_spinlock_t *lock) = 0;
void kfunc_def(_raw_spin_lock_bh)(raw_spinlock_t *lock) = 0;
void kfunc_def(_raw_spin_unlock)(raw_spinlock_t *lock) = 0;
void kfunc_def(_raw_spin_unlock_irqrestore)(raw_spinlock_t *lock, unsigned long flags) = 0;
void kfunc_def(_raw_spin_unlock_irq)(raw_spinlock_t *lock) = 0;
void kfunc_def(_raw_spin_unlock_bh)(raw_spinlock_t *lock) = 0;
int kfunc_def(_raw_read_trylock)(rwlock_t *lock) = 0;
void kfunc_def(_raw_read_lock)(rwlock_t *lock) = 0;
unsigned long kfunc_def(_raw_read_lock_irqsave)(rwlock_t *lock) = 0;
void kfunc_def(_raw_read_lock_irq)(rwlock_t *lock) = 0;
void kfunc_def(_raw_read_lock_bh)(rwlock_t *lock) = 0;
void kfunc_def(_raw_read_unlock)(rwlock_t *lock) = 0;
void kfunc_def(_raw_read_unlock_irqrestore)(rwlock_t *lock, unsigned long flags) = 0;
void kfunc_def(_raw_read_unlock_irq)(rwlock_t *lock) = 0;
void kfunc_def(_raw_read_unlock_bh)(rwlock_t *lock) = 0;
int kfunc_def(_raw_write_trylock)(rwlock_t *lock) = 0;
void kfunc_def(_raw_write_lock)(rwlock_t *lock) = 0;
unsigned long kfunc_def(_raw_write_lock_irqsave)(rwlock_t *lock) = 0;
void kfunc_def(_raw_write_lock_irq)(rwlock_t *lock) = 0;
void kfunc_def(_raw_write_lock_bh)(rwlock_t *lock) = 0;
void kfunc_def(_raw_write_unlock)(rwlock_t *lock) = 0;
void kfunc_def(_raw_write_unlock_irqrestore)(rwlock_t *lock, unsigned long flags) = 0;
void kfunc_def(_raw_write_unlock_irq)(rwlock_t *lock) = 0;
void kfunc_def(_raw_write_unlock_bh)(rwlock_t *lock) = 0;

void _linux_locking_spinlock_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(_raw_spin_trylock, name, addr);
    // kfunc_match(_raw_spin_trylock_bh, name, addr);
    kfunc_match(_raw_spin_lock, name, addr);
    kfunc_match(_raw_spin_lock_irqsave, name, addr);
    kfunc_match(_raw_spin_lock_irq, name, addr);
    // kfunc_match(_raw_spin_lock_bh, name, addr);
    kfunc_match(_raw_spin_unlock, name, addr);
    kfunc_match(_raw_spin_unlock_irqrestore, name, addr);
    kfunc_match(_raw_spin_unlock_irq, name, addr);
    // kfunc_match(_raw_spin_unlock_bh, name, addr);
    // kfunc_match(_raw_read_trylock, name, addr);
    // kfunc_match(_raw_read_lock, name, addr);
    // kfunc_match(_raw_read_lock_irqsave, name, addr);
    // kfunc_match(_raw_read_lock_irq, name, addr);
    // kfunc_match(_raw_read_lock_bh, name, addr);
    // kfunc_match(_raw_read_unlock, name, addr);
    // kfunc_match(_raw_read_unlock_irqrestore, name, addr);
    // kfunc_match(_raw_read_unlock_irq, name, addr);
    // kfunc_match(_raw_read_unlock_bh, name, addr);
    // kfunc_match(_raw_write_trylock, name, addr);
    // kfunc_match(_raw_write_lock, name, addr);
    // kfunc_match(_raw_write_lock_irqsave, name, addr);
    // kfunc_match(_raw_write_lock_irq, name, addr);
    // kfunc_match(_raw_write_lock_bh, name, addr);
    // kfunc_match(_raw_write_unlock, name, addr);
    // kfunc_match(_raw_write_unlock_irqrestore, name, addr);
    // kfunc_match(_raw_write_unlock_irq, name, addr);
    // kfunc_match(_raw_write_unlock_bh, name, addr);
}

// kernel/fork.c
#include <ksyms.h>

struct file;
struct mm_struct;
struct task_struct;
struct kernel_clone_args;
struct files_struct;

struct pid *kfunc_def(pidfd_pid)(const struct file *file) = 0;
void kfunc_def(free_task)(struct task_struct *tsk) = 0;
void kfunc_def(__put_task_struct)(struct task_struct *tsk) = 0;
void kfunc_def(fork_init)(void) = 0;
void kfunc_def(set_mm_exe_file)(struct mm_struct *mm, struct file *new_exe_file) = 0;
struct file *kfunc_def(get_mm_exe_file)(struct mm_struct *mm) = 0;
struct file *kfunc_def(get_task_exe_file)(struct task_struct *task) = 0;
struct mm_struct *kfunc_def(mm_access)(struct task_struct *task, unsigned int mode) = 0;
void kfunc_def(exit_mm_release)(struct task_struct *tsk, struct mm_struct *mm) = 0;
void kfunc_def(exec_mm_release)(struct task_struct *tsk, struct mm_struct *mm) = 0;
struct task_struct *kfunc_def(fork_idle)(int cpu) = 0;
struct mm_struct *kfunc_def(copy_init_mm)(void) = 0;
struct task_struct *kfunc_def(create_io_thread)(int (*fn)(void *), void *arg, int node) = 0;
pid_t kfunc_def(kernel_clone)(struct kernel_clone_args *args) = 0;
pid_t kfunc_def(kernel_thread)(int (*fn)(void *), void *arg, unsigned long flags) = 0;
int kfunc_def(unshare_fd)(unsigned long unshare_flags, unsigned int max_fds, struct files_struct **new_fdp) = 0;
int kfunc_def(ksys_unshare)(unsigned long unshare_flags) = 0;
int kfunc_def(unshare_files)(struct files_struct **displaced) = 0;

static void _linux_kernel_fork_sym_match(const char *name, unsigned long addr)
{
    // kfunc_match(pidfd_pid, name, addr);
    // kfunc_match(get_mm_exe_file, name, addr);
    // kfunc_match(free_task, name, addr);
    // kfunc_match(__put_task_struct, name, addr);
    // kfunc_match(fork_init, name, addr);
    // kfunc_match(set_mm_exe_file, name, addr);
    // kfunc_match(get_mm_exe_file, name, addr);
    // kfunc_match(get_task_exe_file, name, addr);
    // kfunc_match(mm_access, name, addr);
    // kfunc_match(exit_mm_release, name, addr);
    // kfunc_match(exec_mm_release, name, addr);
    // kfunc_match(fork_idle, name, addr);
    // kfunc_match(copy_init_mm, name, addr);
    // kfunc_match(create_io_thread, name, addr);
    // kfunc_match(kernel_clone, name, addr);
    // kfunc_match(kernel_thread, name, addr);
    // kfunc_match(unshare_fd, name, addr);
    // kfunc_match(ksys_unshare, name, addr);
    // kfunc_match(unshare_files, name, addr);
}

// kernel/pid.c
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/sched.h>

struct pid *kfunc_def(pidfd_get_pid)(unsigned int fd, unsigned int *flags) = 0;
void kfunc_def(put_pid)(struct pid *pid) = 0;
struct task_struct *kfunc_def(pid_task)(struct pid *pid, enum pid_type) = 0;
struct task_struct *kfunc_def(get_pid_task)(struct pid *pid, enum pid_type) = 0;
struct pid *kfunc_def(get_task_pid)(struct task_struct *task, enum pid_type type) = 0;
void kfunc_def(attach_pid)(struct task_struct *task, enum pid_type) = 0;
void kfunc_def(detach_pid)(struct task_struct *task, enum pid_type) = 0;
void kfunc_def(change_pid)(struct task_struct *task, enum pid_type, struct pid *pid) = 0;
void kfunc_def(exchange_tids)(struct task_struct *task, struct task_struct *old) = 0;
void kfunc_def(transfer_pid)(struct task_struct *old, struct task_struct *new, enum pid_type) = 0;

pid_t kfunc_def(__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;
struct pid_namespace *kfunc_def(task_active_pid_ns)(struct task_struct *tsk) = 0;
struct pid *kfunc_def(find_pid_ns)(int nr, struct pid_namespace *ns) = 0;
struct pid *kfunc_def(find_vpid)(int nr) = 0;
struct pid *kfunc_def(find_get_pid)(int nr) = 0;
struct pid *kfunc_def(find_ge_pid)(int nr, struct pid_namespace *ns) = 0;
struct pid *kfunc_def(alloc_pid)(struct pid_namespace *ns, pid_t *set_tid, size_t set_tid_size) = 0;
void kfunc_def(free_pid)(struct pid *pid) = 0;
void kfunc_def(disable_pid_allocation)(struct pid_namespace *ns) = 0;
pid_t kfunc_def(pid_nr_ns)(struct pid *pid, struct pid_namespace *ns) = 0;
pid_t kfunc_def(pid_vnr)(struct pid *pid) = 0;

struct task_struct *kfunc_def(find_task_by_vpid)(pid_t nr) = 0;
struct task_struct *kfunc_def(find_task_by_pid_ns)(pid_t nr, struct pid_namespace *ns) = 0;
struct task_struct *kfunc_def(find_get_task_by_vpid)(pid_t nr) = 0;

void _linux_kernel_pid_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(pidfd_get_pid, name, addr);
    kfunc_match(put_pid, name, addr);
    kfunc_match(pid_task, name, addr);
    kfunc_match(get_pid_task, name, addr);
    kfunc_match(get_task_pid, name, addr);
    // kfunc_match(attach_pid, name, addr);
    // kfunc_match(detach_pid, name, addr);
    // kfunc_match(change_pid, name, addr);
    // kfunc_match(exchange_tids, name, addr);
    // kfunc_match(transfer_pid, name, addr);

    kfunc_match(__task_pid_nr_ns, name, addr);
    kfunc_match(task_active_pid_ns, name, addr);
    kfunc_match(find_pid_ns, name, addr);
    kfunc_match(find_vpid, name, addr);
    // kfunc_match(find_get_pid, name, addr);
    // kfunc_match(find_ge_pid, name, addr);
    // kfunc_match(alloc_pid, name, addr);
    // kfunc_match(free_pid, name, addr);
    // kfunc_match(disable_pid_allocation, name, addr);
    kfunc_match(pid_nr_ns, name, addr);
    kfunc_match(pid_vnr, name, addr);

    kfunc_match(find_task_by_vpid, name, addr);
    kfunc_match(find_task_by_pid_ns, name, addr);
    kfunc_match(find_get_task_by_vpid, name, addr);
}

// kernel/stop_machine.c
#include <linux/stop_machine.h>

const struct cpumask *kvar(__cpu_online_mask) = 0;
int kfunc_def(stop_machine)(int (*fn)(void *), void *data, const struct cpumask *cpus) = 0;

static void _linux_kernel_stop_machine_sym_match(const char *name, unsigned long addr)
{
    kvar_match(__cpu_online_mask, name, addr);
    kfunc_match(stop_machine, name, addr);
}

// mm/util.c
struct file;
struct page;
struct address_space;
struct task_struct;

char *kfunc_def(strndup_user)(const char __user *, long) = 0;
void *kfunc_def(memdup_user)(const void __user *, size_t) = 0;
void *kfunc_def(vmemdup_user)(const void __user *, size_t) = 0;
void *kfunc_def(memdup_user_nul)(const void __user *, size_t) = 0;

void kfunc_def(kfree_const)(const void *x) = 0;
char *kfunc_def(kstrdup)(const char *s, gfp_t gfp) = 0;
const char *kfunc_def(kstrdup_const)(const char *s, gfp_t gfp) = 0;
char *kfunc_def(kstrndup)(const char *s, size_t max, gfp_t gfp) = 0;
void *kfunc_def(kmemdup)(const void *src, size_t len, gfp_t gfp) = 0;
char *kfunc_def(kmemdup_nul)(const char *s, size_t len, gfp_t gfp) = 0;
unsigned long kfunc_def(vm_mmap)(struct file *file, unsigned long addr, unsigned long len, unsigned long prot,
                                 unsigned long flag, unsigned long offset) = 0;
void *kfunc_def(kvmalloc_node)(size_t size, gfp_t flags, int node) = 0;
void kfunc_def(kvfree)(const void *addr) = 0;
void kfunc_def(kvfree_sensitive)(const void *addr, size_t len) = 0;
void *kfunc_def(kvrealloc)(const void *p, size_t oldsize, size_t newsize, gfp_t flags) = 0;
bool kfunc_def(page_mapped)(struct page *page) = 0;
struct address_space *kfunc_def(page_mapping)(struct page *page) = 0;
int kfunc_def(__page_mapcount)(struct page *page) = 0;
unsigned long kfunc_def(vm_memory_committed)(void) = 0;
int kfunc_def(get_cmdline)(struct task_struct *task, char *buffer, int buflen) = 0; // not exported

void *kfunc_def(__kmalloc)(size_t size, gfp_t flags) = 0;
void *kfunc_def(kmalloc)(size_t size, gfp_t flags) = 0;
void kfunc_def(kfree)(const void *) = 0;

static void _linux_mm_utils_sym_match(const char *name, unsigned long addr)
{
    // kfunc_match(kfree_const, name, addr);
    // kfunc_match(kstrdup, name, addr);
    // kfunc_match(kstrdup_const, name, addr);
    // kfunc_match(kstrndup, name, addr);
    // kfunc_match(kmemdup, name, addr);
    // kfunc_match(kmemdup_nul, name, addr);
    kfunc_match(memdup_user, name, addr);
    // kfunc_match(vmemdup_user, name, addr);
    kfunc_match(strndup_user, name, addr);
    // kfunc_match(memdup_user_nul, name, addr);
    // kfunc_match(vm_mmap, name, addr);
    // kfunc_match(kvmalloc_node, name, addr);
    kfunc_match(kvfree, name, addr);
    // kfunc_match(kvfree_sensitive, name, addr);
    // kfunc_match(kvrealloc, name, addr);
    // kfunc_match(page_mapped, name, addr);
    // kfunc_match(page_mapping, name, addr);
    // kfunc_match(__page_mapcount, name, addr);
    // kfunc_match(vm_memory_committed, name, addr);
    // kfunc_match(get_cmdline, name, addr);
    // kfunc_match(__kmalloc, name, addr);
    // kfunc_match(kmalloc, name, addr);
    kfunc_match(kfree, name, addr);
}

// mm/vmalloc.c
#include <linux/vmalloc.h>

void kfunc_def(vm_unmap_ram)(const void *mem, unsigned int count) = 0;
void *kfunc_def(vm_map_ram)(struct page **pages, unsigned int count, int node) = 0;
void kfunc_def(vm_unmap_aliases)(void) = 0;

void *kfunc_def(vmalloc)(unsigned long size) = 0;
void *kfunc_def(vmalloc_noprof)(unsigned long size) = 0;
void *kfunc_def(vzalloc)(unsigned long size) = 0;
void *kfunc_def(vmalloc_user)(unsigned long size) = 0;
void *kfunc_def(vmalloc_node)(unsigned long size, int node) = 0;
void *kfunc_def(vzalloc_node)(unsigned long size, int node) = 0;
void *kfunc_def(vmalloc_32)(unsigned long size) = 0;
void *kfunc_def(vmalloc_32_user)(unsigned long size) = 0;
void *kfunc_def(__vmalloc)(unsigned long size, gfp_t gfp_mask) = 0;
void *kfunc_def(__vmalloc_node_range)(unsigned long size, unsigned long align, unsigned long start, unsigned long end,
                                      gfp_t gfp_mask, pgprot_t prot, unsigned long vm_flags, int node,
                                      const void *caller) = 0;
void *kfunc_def(__vmalloc_node)(unsigned long size, unsigned long align, gfp_t gfp_mask, int node,
                                const void *caller) = 0;

void kfunc_def(vfree)(const void *addr) = 0;
void kfunc_def(vfree_atomic)(const void *addr) = 0;

void *kfunc_def(vmap)(struct page **pages, unsigned int count, unsigned long flags, pgprot_t prot) = 0;
void *kfunc_def(vmap_pfn)(unsigned long *pfns, unsigned int count, pgprot_t prot) = 0;
void kfunc_def(vunmap)(const void *addr) = 0;
int kfunc_def(remap_vmalloc_range_partial)(struct vm_area_struct *vma, unsigned long uaddr, void *kaddr,
                                           unsigned long pgoff, unsigned long size) = 0;
int kfunc_def(remap_vmalloc_range)(struct vm_area_struct *vma, void *addr, unsigned long pgoff) = 0;

struct vm_struct *kfunc_def(get_vm_area)(unsigned long size, unsigned long flags) = 0;
struct vm_struct *kfunc_def(get_vm_area_caller)(unsigned long size, unsigned long flags, const void *caller) = 0;
struct vm_struct *kfunc_def(__get_vm_area_caller)(unsigned long size, unsigned long flags, unsigned long start,
                                                  unsigned long end, const void *caller) = 0;
void kfunc_def(free_vm_area)(struct vm_struct *area) = 0;
struct vm_struct *kfunc_def(remove_vm_area)(const void *addr) = 0;
struct vm_struct *kfunc_def(find_vm_area)(const void *addr) = 0;

int kfunc_def(map_kernel_range_noflush)(unsigned long start, unsigned long size, pgprot_t prot,
                                        struct page **pages) = 0;
int kfunc_def(map_kernel_range)(unsigned long start, unsigned long size, pgprot_t prot, struct page **pages) = 0;
void kfunc_def(unmap_kernel_range_noflush)(unsigned long addr, unsigned long size) = 0;
void kfunc_def(unmap_kernel_range)(unsigned long addr, unsigned long size) = 0;

long kfunc_def(vread)(char *buf, char *addr, unsigned long count) = 0;
long kfunc_def(vwrite)(char *buf, char *addr, unsigned long count) = 0;

static void _linux_mm_vmalloc_sym_match(const char *name, unsigned long addr)
{
    // kfunc_match(vm_unmap_ram, name, addr);
    // kfunc_match(vm_map_ram, name, addr);
    // kfunc_match(vm_unmap_aliases, name, addr);

    kfunc_match(vmalloc, name, addr);
    kfunc_match(vmalloc_noprof, name, addr);
    kfunc_match(vzalloc, name, addr);
    // kfunc_match(vmalloc_user, name, addr);
    // kfunc_match(vmalloc_node, name, addr);
    // kfunc_match(vzalloc_node, name, addr);
    // kfunc_match(vmalloc_32, name, addr);
    // kfunc_match(vmalloc_32_user, name, addr);
    kfunc_match(__vmalloc, name, addr);
    // kfunc_match(__vmalloc_node_range, name, addr);
    // kfunc_match(__vmalloc_node, name, addr);

    kfunc_match(vfree, name, addr);
    // kfunc_match(vfree_atomic, name, addr);

    // kfunc_match(vmap, name, addr);
    // kfunc_match(vmap_pfn, name, addr);
    // kfunc_match(vunmap, name, addr);
    // kfunc_match(remap_vmalloc_range_partial, name, addr);
    // kfunc_match(remap_vmalloc_range, name, addr);

    // kfunc_match(get_vm_area, name, addr);
    // kfunc_match(get_vm_area_caller, name, addr);
    // kfunc_match(__get_vm_area_caller, name, addr);
    // kfunc_match(free_vm_area, name, addr);
    // kfunc_match(remove_vm_area, name, addr);
    // kfunc_match(find_vm_area, name, addr);

    // kfunc_match(map_kernel_range_noflush, name, addr);
    // kfunc_match(map_kernel_range, name, addr);
    // kfunc_match(unmap_kernel_range_noflush, name, addr);
    // kfunc_match(unmap_kernel_range, name, addr);

    // kfunc_match(vread, name, addr);
    // kfunc_match(vwrite, name, addr);
}

#include <linux/fs.h>

void kfunc_def(inc_nlink)(struct inode *inode) = 0;
void kfunc_def(drop_nlink)(struct inode *inode) = 0;
void kfunc_def(clear_nlink)(struct inode *inode) = 0;
void kfunc_def(set_nlink)(struct inode *inode, unsigned int nlink) = 0;

ssize_t kfunc_def(kernel_read)(struct file *file, void *buf, size_t count, loff_t *pos) = 0;
ssize_t kfunc_def(kernel_write)(struct file *file, const void *buf, size_t count, loff_t *pos) = 0;
struct file *kfunc_def(open_exec)(const char *) = 0;

struct file *kfunc_def(file_open_name)(struct filename *, int, umode_t) = 0;
struct file *kfunc_def(filp_open)(const char *, int, umode_t) = 0;
struct file *kfunc_def(file_open_root)(struct dentry *, struct vfsmount *, const char *, int, umode_t) = 0;
struct file *kfunc_def(dentry_open)(const struct path *, int, const struct cred *) = 0;
int kfunc_def(filp_close)(struct file *, fl_owner_t id) = 0;

struct filename *kfunc_def(getname)(const char __user *) = 0;
struct filename *kfunc_def(getname_kernel)(const char *) = 0;
void kfunc_def(putname)(struct filename *name) = 0;
void kfunc_def(final_putname)(struct filename *name) = 0;

loff_t kfunc_def(vfs_llseek)(struct file *file, loff_t offset, int whence) = 0;

static void _linux_fs_sym_match(const char *name, unsigned long addr)
{
    // kfunc_match(inc_nlink, name, addr);
    // kfunc_match(drop_nlink, name, addr);
    // kfunc_match(clear_nlink, name, addr);
    // kfunc_match(set_nlink, name, addr);
    kfunc_match(kernel_read, name, addr);
    kfunc_match(kernel_write, name, addr);
    // kfunc_match(open_exec, name, addr);
    kfunc_match(file_open_name, name, addr);
    kfunc_match(filp_open, name, addr);
    // kfunc_match(file_open_root, name, addr);
    // kfunc_match(dentry_open, name, addr);
    kfunc_match(filp_close, name, addr);
    // kfunc_match(getname, name, addr);
    // kfunc_match(getname_kernel, name, addr);
    // kfunc_match(putname, name, addr);
    // kfunc_match(final_putname, name, addr);
    kfunc_match(vfs_llseek, name, addr);
}

#include <linux/stacktrace.h>

void kfunc_def(save_stack_trace)(struct stack_trace *trace) = 0;
void kfunc_def(save_stack_trace_regs)(struct pt_regs *regs, struct stack_trace *trace) = 0;
void kfunc_def(save_stack_trace_tsk)(struct task_struct *tsk, struct stack_trace *trace) = 0;
void kfunc_def(print_stack_trace)(struct stack_trace *trace, int spaces) = 0;
void kfunc_def(save_stack_trace_user)(struct stack_trace *trace) = 0;

static void _linux_stacktrace_sym_match(const char *name, unsigned long addr)
{
    // kfunc_match(save_stack_trace, name, addr);
    // kfunc_match(save_stack_trace_regs, name, addr);
    kfunc_match(save_stack_trace_tsk, name, addr);
    // kfunc_match(print_stack_trace, name, addr);
    // kfunc_match(save_stack_trace_user, name, addr);
}

#include <security/selinux/include/avc.h>

int kfunc_def(avc_denied)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u8 driver, u8 xperm, unsigned int flags,
                          struct av_decision *avd) = 0;
int kfunc_def(slow_avc_audit)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited,
                              u32 denied, int result, struct common_audit_data *a) = 0;

int kfunc_def(avc_has_perm_noaudit)(u32 ssid, u32 tsid, u16 tclass, u32 requested, unsigned flags,
                                    struct av_decision *avd) = 0;
int kfunc_def(avc_has_perm)(u32 ssid, u32 tsid, u16 tclass, u32 requested, struct common_audit_data *auditdata) = 0;
int kfunc_def(avc_has_perm_flags)(u32 ssid, u32 tsid, u16 tclass, u32 requested, struct common_audit_data *auditdata,
                                  int flags) = 0;
int kfunc_def(avc_has_extended_perms)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u8 driver, u8 perm,
                                      struct common_audit_data *ad) = 0;
struct avc_node *kfunc_def(avc_lookup)(u32 ssid, u32 tsid, u16 tclass) = 0;
struct avc_node *kfunc_def(avc_compute_av)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd,
                                           struct avc_xperms_node *xp_node) = 0;

static void _linux_security_selinux_avc_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(avc_denied, name, addr);
    kfunc_match(slow_avc_audit, name, addr);

    // kfunc_match(avc_has_perm_noaudit, name, addr);
    // kfunc_match(avc_has_perm, name, addr);
    // kfunc_match(avc_has_perm_flags, name, addr);
    // kfunc_match(avc_has_extended_perms, name, addr);
    // kfunc_match(avc_lookup, name, addr);
    // kfunc_match(avc_compute_av, name, addr);
}

#include <security/selinux/include/security.h>
#include <security/selinux/include/classmap.h>

int kvar_def(selinux_enabled_boot) = 0;
int kvar_def(selinux_enabled) = 0;
struct selinux_state kvar_def(selinux_state) = 0;
struct security_class_mapping kvar_def(secclass_map)[] = 0;

int kfunc_def(security_mls_enabled)(void) = 0;
int kfunc_def(security_load_policy)(void *data, size_t len, struct selinux_load_state *load_state) = 0;
void kfunc_def(selinux_policy_commit)(struct selinux_load_state *load_state) = 0;
void kfunc_def(selinux_policy_cancel)(struct selinux_load_state *load_state) = 0;
int kfunc_def(security_read_policy)(void **data, size_t *len) = 0;
int kfunc_def(security_read_state_kernel)(void **data, size_t *len) = 0;
int kfunc_def(security_policycap_supported)(unsigned int req_cap) = 0;
void kfunc_def(security_compute_av)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd,
                                    struct extended_perms *xperms) = 0;
void kfunc_def(security_compute_xperms_decision)(u32 ssid, u32 tsid, u16 tclass, u8 driver,
                                                 struct extended_perms_decision *xpermd) = 0;
void kfunc_def(security_compute_av_user)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd) = 0;
int kfunc_def(security_transition_sid)(u32 ssid, u32 tsid, u16 tclass, const struct qstr *qstr, u32 *out_sid) = 0;
int kfunc_def(security_transition_sid_user)(u32 ssid, u32 tsid, u16 tclass, const char *objname, u32 *out_sid) = 0;
int kfunc_def(security_member_sid)(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid) = 0;
int kfunc_def(security_change_sid)(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid) = 0;
int kfunc_def(security_sid_to_context)(u32 sid, char **scontext, u32 *scontext_len) = 0;
int kfunc_def(security_sid_to_context_force)(u32 sid, char **scontext, u32 *scontext_len) = 0;
int kfunc_def(security_sid_to_context_inval)(u32 sid, char **scontext, u32 *scontext_len) = 0;
int kfunc_def(security_context_to_sid)(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp) = 0;
int kfunc_def(security_context_str_to_sid)(const char *scontext, u32 *out_sid, gfp_t gfp) = 0;
int kfunc_def(security_context_to_sid_default)(const char *scontext, u32 scontext_len, u32 *out_sid, u32 def_sid,
                                               gfp_t gfp_flags) = 0;
int kfunc_def(security_context_to_sid_force)(const char *scontext, u32 scontext_len, u32 *sid) = 0;
int kfunc_def(security_get_user_sids)(u32 callsid, char *username, u32 **sids, u32 *nel) = 0;
int kfunc_def(security_port_sid)(u8 protocol, u16 port, u32 *out_sid) = 0;
int kfunc_def(security_ib_pkey_sid)(u64 subnet_prefix, u16 pkey_num, u32 *out_sid) = 0;
int kfunc_def(security_ib_endport_sid)(const char *dev_name, u8 port_num, u32 *out_sid) = 0;
int kfunc_def(security_netif_sid)(char *name, u32 *if_sid) = 0;
int kfunc_def(security_node_sid)(u16 domain, void *addr, u32 addrlen, u32 *out_sid) = 0;
int kfunc_def(security_validate_transition)(u32 oldsid, u32 newsid, u32 tasksid, u16 tclass) = 0;
int kfunc_def(security_validate_transition_user)(u32 oldsid, u32 newsid, u32 tasksid, u16 tclass) = 0;
int kfunc_def(security_bounded_transition)(u32 oldsid, u32 newsid) = 0;
int kfunc_def(security_sid_mls_copy)(u32 sid, u32 mls_sid, u32 *new_sid) = 0;
int kfunc_def(security_net_peersid_resolve)(u32 nlbl_sid, u32 nlbl_type, u32 xfrm_sid, u32 *peer_sid) = 0;
int kfunc_def(security_get_classes)(struct selinux_policy *policy, char ***classes, int *nclasses) = 0;
int kfunc_def(security_get_permissions)(struct selinux_policy *policy, char *class, char ***perms, int *nperms) = 0;
int kfunc_def(security_get_reject_unknown)(void) = 0;
int kfunc_def(security_get_allow_unknown)(void) = 0;

int kfunc_def(security_fs_use)(struct super_block *sb) = 0;
int kfunc_def(security_genfs_sid)(const char *fstype, const char *path, u16 sclass, u32 *sid) = 0;
int kfunc_def(selinux_policy_genfs_sid)(struct selinux_policy *policy, const char *fstype, const char *path, u16 sclass,
                                        u32 *sid) = 0;
int kfunc_def(security_netlbl_secattr_to_sid)(struct netlbl_lsm_secattr *secattr, u32 *sid) = 0;
int kfunc_def(security_netlbl_sid_to_secattr)(u32 sid, struct netlbl_lsm_secattr *secattr) = 0;
const char *kfunc_def(security_get_initial_sid_context)(u32 sid) = 0;

void kfunc_def(selinux_status_update_setenforce)(int enforcing) = 0;
void kfunc_def(selinux_status_update_policyload)(int seqno) = 0;
void kfunc_def(selinux_complete_init)(void) = 0;
void kfunc_def(exit_sel_fs)(void) = 0;
void kfunc_def(selnl_notify_setenforce)(int val) = 0;
void kfunc_def(selnl_notify_policyload)(u32 seqno) = 0;
int kfunc_def(selinux_nlmsg_lookup)(u16 sclass, u16 nlmsg_type, u32 *perm) = 0;

void kfunc_def(avtab_cache_init)(void) = 0;
void kfunc_def(ebitmap_cache_init)(void) = 0;
void kfunc_def(hashtab_cache_init)(void) = 0;
int kfunc_def(security_sidtab_hash_stats)(char *page) = 0;

static void _linux_security_selinux_sym_match(const char *name, unsigned long addr)
{
    // kvar_match(selinux_enabled_boot, name, addr);
    // kvar_match(selinux_enabled, name, addr);
    // kvar_match(selinux_state, name, addr);
    // kvar_match(secclass_map, name, addr);
    // kfunc_match(security_mls_enabled, name, addr);
    // kfunc_match(security_load_policy, name, addr);
    // kfunc_match(selinux_policy_commit, name, addr);
    // kfunc_match(selinux_policy_cancel, name, addr);
    // kfunc_match(security_read_policy, name, addr);
    // kfunc_match(security_read_state_kernel, name, addr);
    // kfunc_match(security_policycap_supported, name, addr);
    // kfunc_match(security_compute_av, name, addr);
    // kfunc_match(security_compute_xperms_decision, name, addr);
    // kfunc_match(security_compute_av_user, name, addr);
    // kfunc_match(security_transition_sid, name, addr);
    // kfunc_match(security_transition_sid_user, name, addr);
    // kfunc_match(security_member_sid, name, addr);
    // kfunc_match(security_change_sid, name, addr);
    // kfunc_match(security_sid_to_context, name, addr);
    // kfunc_match(security_sid_to_context_force, name, addr);
    // kfunc_match(security_sid_to_context_inval, name, addr);
    // kfunc_match(security_context_to_sid, name, addr);
    // kfunc_match(security_context_str_to_sid, name, addr);
    // kfunc_match(security_context_to_sid_default, name, addr);
    // kfunc_match(security_context_to_sid_force, name, addr);
    // kfunc_match(security_get_user_sids, name, addr);
    // kfunc_match(security_port_sid, name, addr);
    // kfunc_match(security_ib_pkey_sid, name, addr);
    // kfunc_match(security_ib_endport_sid, name, addr);
    // kfunc_match(security_netif_sid, name, addr);
    // kfunc_match(security_node_sid, name, addr);
    // kfunc_match(security_validate_transition, name, addr);
    // kfunc_match(security_validate_transition_user, name, addr);
    // kfunc_match(security_bounded_transition, name, addr);
    // kfunc_match(security_sid_mls_copy, name, addr);
    // kfunc_match(security_net_peersid_resolve, name, addr);
    // kfunc_match(security_get_classes, name, addr);
    // kfunc_match(security_get_permissions, name, addr);
    // kfunc_match(security_get_reject_unknown, name, addr);
    // kfunc_match(security_get_allow_unknown, name, addr);

    // kfunc_match(security_fs_use, name, addr);
    // kfunc_match(security_genfs_sid, name, addr);
    // kfunc_match(selinux_policy_genfs_sid, name, addr);
    // kfunc_match(security_netlbl_secattr_to_sid, name, addr);
    // kfunc_match(security_netlbl_sid_to_secattr, name, addr);
    // kfunc_match(security_get_initial_sid_context, name, addr);

    // kfunc_match(selinux_status_update_setenforce, name, addr);
    // kfunc_match(selinux_status_update_policyload, name, addr);
    // kfunc_match(selinux_complete_init, name, addr);
    // kfunc_match(exit_sel_fs, name, addr);
    // kfunc_match(selnl_notify_setenforce, name, addr);
    // kfunc_match(selnl_notify_policyload, name, addr);
    // kfunc_match(selinux_nlmsg_lookup, name, addr);

    // kfunc_match(avtab_cache_init, name, addr);
    // kfunc_match(ebitmap_cache_init, name, addr);
    // kfunc_match(hashtab_cache_init, name, addr);
    // kfunc_match(security_sidtab_hash_stats, name, addr);
}

#include <linux/security.h>

int kfunc_def(cap_capable)(const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts) = 0;
int kfunc_def(cap_settime)(const struct timespec64 *ts, const struct timezone *tz) = 0;
int kfunc_def(cap_ptrace_access_check)(struct task_struct *child, unsigned int mode) = 0;
int kfunc_def(cap_ptrace_traceme)(struct task_struct *parent) = 0;
int kfunc_def(cap_capget)(struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable,
                          kernel_cap_t *permitted) = 0;
int kfunc_def(cap_capset)(struct cred *new, const struct cred *old, const kernel_cap_t *effective,
                          const kernel_cap_t *inheritable, const kernel_cap_t *permitted) = 0;
int kfunc_def(cap_bprm_creds_from_file)(struct linux_binprm *bprm, struct file *file) = 0;
int kfunc_def(cap_inode_setxattr)(struct dentry *dentry, const char *name, const void *value, size_t size,
                                  int flags) = 0;
int kfunc_def(cap_inode_removexattr)(struct dentry *dentry, const char *name) = 0;
int kfunc_def(cap_inode_need_killpriv)(struct dentry *dentry) = 0;
int kfunc_def(cap_inode_killpriv)(struct dentry *dentry) = 0;
int kfunc_def(cap_inode_getsecurity)(struct inode *inode, const char *name, void **buffer, bool alloc) = 0;
int kfunc_def(cap_mmap_addr)(unsigned long addr) = 0;
int kfunc_def(cap_mmap_file)(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags) = 0;
int kfunc_def(cap_task_fix_setuid)(struct cred *new, const struct cred *old, int flags) = 0;
int kfunc_def(cap_task_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
                              unsigned long arg5) = 0;
int kfunc_def(cap_task_setscheduler)(struct task_struct *p) = 0;
int kfunc_def(cap_task_setioprio)(struct task_struct *p, int ioprio) = 0;
int kfunc_def(cap_task_setnice)(struct task_struct *p, int nice) = 0;
int kfunc_def(cap_vm_enough_memory)(struct mm_struct *mm, long pages) = 0;
// int kfunc_def(security_secid_to_secctx)(u32 secid, char **secdata, u32 *seclen) = 0;
int kfunc_def(security_secctx_to_secid)(const char *secdata, u32 seclen, u32 *secid) = 0;

kernel_cap_t full_cap = { 0 };

static void _linux_security_commoncap_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(cap_capable, name, addr);
    // kfunc_match(cap_settime, name, addr);
    // kfunc_match(cap_ptrace_access_check, name, addr);
    // kfunc_match(cap_ptrace_traceme, name, addr);
    kfunc_match(cap_capget, name, addr);
    kfunc_match(cap_capset, name, addr);
    // kfunc_match(cap_bprm_creds_from_file, name, addr);
    // kfunc_match(cap_inode_setxattr, name, addr);
    // kfunc_match(cap_inode_removexattr, name, addr);
    // kfunc_match(cap_inode_need_killpriv, name, addr);
    // kfunc_match(cap_inode_killpriv, name, addr);
    // kfunc_match(cap_inode_getsecurity, name, addr);
    // kfunc_match(cap_mmap_addr, name, addr);
    // kfunc_match(cap_mmap_file, name, addr);
    // kfunc_match(cap_task_fix_setuid, name, addr);
    kfunc_match(cap_task_prctl, name, addr);
    // kfunc_match(cap_task_setscheduler, name, addr);
    // kfunc_match(cap_task_setioprio, name, addr);
    // kfunc_match(cap_task_setnice, name, addr);
    // kfunc_match(security_secid_to_secctx, name, addr);
    kfunc_match(security_secctx_to_secid, name, addr);
}

#include <linux/seccomp.h>

long kfunc_def(prctl_get_seccomp)(void) = 0;
long kfunc_def(prctl_set_seccomp)(unsigned long seccomp_mode, char __user *filter) = 0;

void kfunc_def(put_seccomp_filter)(struct task_struct *tsk) = 0;
void kfunc_def(get_seccomp_filter)(struct task_struct *tsk) = 0;

void kfunc_def(seccomp_filter_release)(struct task_struct *tsk) = 0;

static void _linux_seccomp_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(prctl_get_seccomp, name, addr);
    // kfunc_match(prctl_set_seccomp, name, addr);
    // kfunc_match(put_seccomp_filter, name, addr);
    // kfunc_match(get_seccomp_filter, name, addr);
    // kfunc_match(seccomp_filter_release, name, addr);
}

#include <linux/panic.h>
#include <linux/umh.h>

void kfunc_def(panic)(const char *fmt, ...) __noreturn __cold = 0;
int kfunc_def(call_usermodehelper)(const char *path, char **argv, char **envp, int wait) = 0;

// /drivers/char/random.c
void kfunc_def(get_random_bytes)(void *buf, int nbytes) = 0;
uint64_t kfunc_def(get_random_u64)(void) = 0;
uint64_t kfunc_def(get_random_long)(void) = 0;

static void _linux_misc_misc(const char *name, unsigned long addr)
{
    kfunc_match(panic, name, addr);
    // kfunc_match(call_usermodehelper, name, addr);
    // kfunc_match(get_random_bytes, name, addr);
    // kfunc_match(get_random_u64, name, addr);
    // kfunc_match(get_random_long, name, addr);
}

// linux/bottom_half.h
struct rcu_gp_oldstate;
void kfunc_def(__local_bh_disable_ip)(unsigned long ip, unsigned int cnt) = 0;
void kfunc_def(__local_bh_enable_ip)(unsigned long ip, unsigned int cnt) = 0;
void kfunc_def(_local_bh_enable)(void) = 0;
bool kfunc_def(local_bh_blocked)(void) = 0;

void kfunc_def(call_rcu)(struct rcu_head *head, rcu_callback_t func);
void kfunc_def(rcu_barrier_tasks)(void);
void kfunc_def(rcu_barrier_tasks_rude)(void);
void kfunc_def(synchronize_rcu)(void);
unsigned long kfunc_def(get_completed_synchronize_rcu)(void);
void kfunc_def(get_completed_synchronize_rcu_full)(struct rcu_gp_oldstate *rgosp);

void kfunc_def(__rcu_read_lock)(void);
void kfunc_def(__rcu_read_unlock)(void);
void kfunc_def(rcu_read_unlock_strict)(void);

// linux/rcupdate
void kfunc_def(rcu_init)(void) = 0;
void kfunc_def(rcu_sched_clock_irq)(int user) = 0;
void kfunc_def(rcu_report_dead)(unsigned int cpu) = 0;
void kfunc_def(rcutree_migrate_callbacks)(int cpu) = 0;

void kfunc_def(rcu_init_tasks_generic)(void) = 0;

void kfunc_def(rcu_sysrq_start)(void) = 0;
void kfunc_def(rcu_sysrq_end)(void) = 0;
void kfunc_def(rcu_irq_work_resched)(void) = 0;

int kfunc_def(rcu_read_lock_held)(void) = 0;
int kfunc_def(rcu_read_lock_bh_held)(void) = 0;
int kfunc_def(rcu_read_lock_sched_held)(void) = 0;
int kfunc_def(rcu_read_lock_any_held)(void) = 0;

void kfunc_def(rcu_init_nohz)(void) = 0;
int kfunc_def(rcu_nocb_cpu_offload)(int cpu) = 0;
int kfunc_def(rcu_nocb_cpu_deoffload)(int cpu) = 0;
void kfunc_def(rcu_nocb_flush_deferred_wakeup)(void) = 0;

void kfunc_def(exit_tasks_rcu_start)(void) = 0;
void kfunc_def(exit_tasks_rcu_stop)(void) = 0;
void kfunc_def(exit_tasks_rcu_finish)(void) = 0;

static void _linux_rcu_symbol_init(const char *name, unsigned long addr)
{
    // kfunc_match(__local_bh_disable_ip, name, addr);
    // kfunc_match(__local_bh_enable_ip, name, addr);
    kfunc_match(_local_bh_enable, name, addr);
    kfunc_match(local_bh_blocked, name, addr);

    kfunc_match(call_rcu, name, addr);
    // kfunc_match(rcu_barrier_tasks, name, addr);
    // kfunc_match(rcu_barrier_tasks_rude, name, addr);
    kfunc_match(synchronize_rcu, name, addr);
    // kfunc_match(get_completed_synchronize_rcu, name, addr);
    // kfunc_match(get_completed_synchronize_rcu_full, name, addr);

    kfunc_match(__rcu_read_lock, name, addr);
    kfunc_match(__rcu_read_unlock, name, addr);
    // kfunc_match(rcu_read_unlock_strict, name, addr);

    // kfunc_match(rcu_init, name, addr);
    // kfunc_match(rcu_sched_clock_irq, name, addr);
    // kfunc_match(rcu_report_dead, name, addr);
    // kfunc_match(rcutree_migrate_callbacks, name, addr);

    // kfunc_match(rcu_init_tasks_generic, name, addr);

    // kfunc_match(rcu_sysrq_start, name, addr);
    // kfunc_match(rcu_sysrq_end, name, addr);
    // kfunc_match(rcu_irq_work_resched, name, addr);

    // kfunc_match(rcu_read_lock_held, name, addr);
    // kfunc_match(rcu_read_lock_bh_held, name, addr);
    // kfunc_match(rcu_read_lock_sched_held, name, addr);
    // kfunc_match(rcu_read_lock_any_held, name, addr);

    // kfunc_match(rcu_init_nohz, name, addr);
    // kfunc_match(rcu_nocb_cpu_offload, name, addr);
    // kfunc_match(rcu_nocb_cpu_deoffload, name, addr);
    // kfunc_match(rcu_nocb_flush_deferred_wakeup, name, addr);

    // kfunc_match(exit_tasks_rcu_start, name, addr);
    // kfunc_match(exit_tasks_rcu_stop, name, addr);
    // kfunc_match(exit_tasks_rcu_finish, name, addr);
}

void kfunc_def(mmput)(struct mm_struct *);
void kfunc_def(mmput_async)(struct mm_struct *);
struct mm_struct *kfunc_def(get_task_mm)(struct task_struct *task);

static void _linux_sched_mm_init(const char *name, unsigned long addr)
{
    kfunc_match(mmput, name, addr);
    kfunc_match(mmput_async, name, addr);
    kfunc_match(get_task_mm, name, addr);
}

static int _linux_misc_symbol_init(void *data, const char *name, struct module *m, unsigned long addr)
{
    _linux_kernel_cred_sym_match(name, addr);
    _linux_kernel_pid_sym_match(name, addr);
    _linux_kernel_stop_machine_sym_match(name, addr);
    _linux_mm_utils_sym_match(name, addr);
    _linux_mm_vmalloc_sym_match(name, addr);
    _linux_fs_sym_match(name, addr);
    _linux_locking_spinlock_sym_match(name, addr);
    _linux_stacktrace_sym_match(name, addr);
    _linux_security_selinux_sym_match(name, addr);
    _linux_security_commoncap_sym_match(name, addr);
    _linux_misc_misc(name, addr);
    _linux_security_selinux_avc_sym_match(name, addr);
    _linux_kernel_fork_sym_match(name, addr);
    _linux_rcu_symbol_init(name, addr);
    _linux_seccomp_sym_match(name, addr);
    _linux_sched_mm_init(name, addr);
    return 0;
}

void linux_misc_symbol_init()
{
#ifdef INIT_USE_KALLSYMS_LOOKUP_NAME
    _linux_misc_symbol_init(0, 0, 0, 0);
#else
    kallsyms_on_each_symbol(_linux_misc_symbol_init, 0);
#endif
}
