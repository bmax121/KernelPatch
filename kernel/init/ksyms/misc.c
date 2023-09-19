#include <ksyms.h>
#include <ktypes.h>

// init/init_task.c  kernel/cred.c
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/sched/task.h>

struct task_struct *kvar(init_task) = 0;
union thread_union *kvar(init_thread_union) = 0;

void _linux_init_task_sym_match()
{
    kvar_match(init_task, name, addr);
    kvar_match(init_thread_union, name, addr);
}

struct cred *kvar(init_cred) = 0;
struct group_info *kvar(init_groups) = 0;

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

void _linux_kernel_cred_sym_match()
{
    kvar_match(init_cred, name, addr);
    kvar_match(init_groups, name, addr);
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
    // kfunc_match(set_security_override, name, addr);
    // kfunc_match(set_security_override_from_ctx, name, addr);
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

void _linux_locking_spinlock_sym_match()
{
    // kfunc_match(_raw_spin_trylock, name, addr);
    // kfunc_match(_raw_spin_trylock_bh, name, addr);
    // kfunc_match(_raw_spin_lock, name, addr);
    // kfunc_match(_raw_spin_lock_irqsave, name, addr);
    // kfunc_match(_raw_spin_lock_irq, name, addr);
    // kfunc_match(_raw_spin_lock_bh, name, addr);
    // kfunc_match(_raw_spin_unlock, name, addr);
    // kfunc_match(_raw_spin_unlock_irqrestore, name, addr);
    // kfunc_match(_raw_spin_unlock_irq, name, addr);
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
struct mm_struct *kfunc_def(get_task_mm)(struct task_struct *task) = 0;
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

void _linux_kernel_fork_sym_match()
{
    // kfunc_match(pidfd_pid, name, addr);
    // kfunc_match(get_mm_exe_file, name, addr);
    // kfunc_match(free_task, name, addr);
    // kfunc_match(__put_task_struct, name, addr);
    // kfunc_match(fork_init, name, addr);
    // kfunc_match(set_mm_exe_file, name, addr);
    // kfunc_match(get_mm_exe_file, name, addr);
    // kfunc_match(get_task_exe_file, name, addr);
    // kfunc_match(get_task_mm, name, addr);
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

void _linux_kernel_pid_sym_match()
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

int kfunc_def(stop_machine)(int (*fn)(void *), void *data, const struct cpumask *cpus) = 0;

void _linux_kernel_stop_machine_sym_match()
{
    kfunc_match(stop_machine, name, addr);
}

// lib/argv_split.c

void kfunc_def(argv_free)(char **argv) = 0;
char **kfunc_def(argv_split)(gfp_t gfp, const char *str, int *argcp) = 0;

void _linux_lib_argv_split_sym_match()
{
    // kfunc_match(argv_free, name, addr);
    // kfunc_match(argv_split, name, addr);
}

// lib/kstrtox.c
int kfunc_def(kstrtoull)(const char *s, unsigned int base, unsigned long long *res) = 0;
int kfunc_def(kstrtoll)(const char *s, unsigned int base, long long *res) = 0;
int kfunc_def(kstrtouint)(const char *s, unsigned int base, unsigned int *res) = 0;
int kfunc_def(kstrtoint)(const char *s, unsigned int base, int *res) = 0;
int kfunc_def(kstrtou16)(const char *s, unsigned int base, u16 *res) = 0;
int kfunc_def(kstrtos16)(const char *s, unsigned int base, s16 *res) = 0;
int kfunc_def(kstrtou8)(const char *s, unsigned int base, u8 *res) = 0;
int kfunc_def(kstrtos8)(const char *s, unsigned int base, s8 *res) = 0;
int kfunc_def(kstrtobool)(const char *s, bool *res) = 0;
int kfunc_def(kstrtobool_from_user)(const char __user *s, size_t count, bool *res) = 0;

void _linxu_lib_kstrtox_sym_match()
{
    // kfunc_match(kstrtoull, name, addr);
    // kfunc_match(kstrtoll, name, addr);
    // kfunc_match(kstrtouint, name, addr);
    // kfunc_match(kstrtoint, name, addr);
    // kfunc_match(kstrtou16, name, addr);
    // kfunc_match(kstrtos16, name, addr);
    // kfunc_match(kstrtou8, name, addr);
    // kfunc_match(kstrtos8, name, addr);
    // kfunc_match(kstrtobool, name, addr);
    // kfunc_match(kstrtobool_from_user, name, addr);
}

// lib/string.c
#include <linux/string.h>

int kfunc_def(strncasecmp)(const char *s1, const char *s2, size_t len) = 0;
int kfunc_def(strcasecmp)(const char *s1, const char *s2) = 0;
char *kfunc_def(strcpy)(char *dest, const char *src) = 0;
char *kfunc_def(strncpy)(char *dest, const char *src, size_t count) = 0;
size_t kfunc_def(strlcpy)(char *dest, const char *src, size_t size) = 0;
ssize_t kfunc_def(strscpy)(char *dest, const char *src, size_t count) = 0;
ssize_t kfunc_def(strscpy_pad)(char *dest, const char *src, size_t count) = 0;
char *kfunc_def(stpcpy)(char *__restrict__ dest, const char *__restrict__ src) = 0;
char *kfunc_def(strcat)(char *dest, const char *src) = 0;
char *kfunc_def(strncat)(char *dest, const char *src, size_t count) = 0;
size_t kfunc_def(strlcat)(char *dest, const char *src, size_t count) = 0;
int kfunc_def(strcmp)(const char *cs, const char *ct) = 0;
int kfunc_def(strncmp)(const char *cs, const char *ct, size_t count) = 0;
char *kfunc_def(strchr)(const char *s, int c) = 0;
char *kfunc_def(strchrnul)(const char *s, int c) = 0;
char *kfunc_def(strnchrnul)(const char *s, size_t count, int c) = 0;
char *kfunc_def(strrchr)(const char *s, int c) = 0;
char *kfunc_def(strnchr)(const char *s, size_t count, int c) = 0;
char *kfunc_def(skip_spaces)(const char *str) = 0;
char *kfunc_def(strim)(char *s) = 0;
size_t kfunc_def(strlen)(const char *s) = 0;
size_t kfunc_def(strnlen)(const char *s, size_t count) = 0;
size_t kfunc_def(strspn)(const char *s, const char *accept) = 0;
size_t kfunc_def(strcspn)(const char *s, const char *reject) = 0;
char *kfunc_def(strpbrk)(const char *cs, const char *ct) = 0;
char *kfunc_def(strsep)(char **s, const char *ct) = 0;
bool kfunc_def(sysfs_streq)(const char *s1, const char *s2) = 0;
int kfunc_def(match_string)(const char *const *array, size_t n, const char *string) = 0;
int kfunc_def(__sysfs_match_string)(const char *const *array, size_t n, const char *str) = 0;
void *kfunc_def(memset)(void *s, int c, size_t count) = 0;
void *kfunc_def(memset16)(uint16_t *s, uint16_t v, size_t count) = 0;
void *kfunc_def(memset32)(uint32_t *s, uint32_t v, size_t count) = 0;
void *kfunc_def(memset64)(uint64_t *s, uint64_t v, size_t count) = 0;
void *kfunc_def(memcpy)(void *dest, const void *src, size_t count) = 0;
void *kfunc_def(memmove)(void *dest, const void *src, size_t count) = 0;
int kfunc_def(memcmp)(const void *cs, const void *ct, size_t count) = 0;
int kfunc_def(bcmp)(const void *a, const void *b, size_t len) = 0;
void *kfunc_def(memscan)(void *addr, int c, size_t size) = 0;
char *kfunc_def(strstr)(const char *s1, const char *s2) = 0;
char *kfunc_def(strnstr)(const char *s1, const char *s2, size_t len) = 0;
void *kfunc_def(memchr)(const void *s, int c, size_t n) = 0;
void *kfunc_def(memchr_inv)(const void *start, int c, size_t bytes) = 0;
char *kfunc_def(strreplace)(char *s, char old, char new) = 0;
void kfunc_def(fortify_panic)(const char *name) = 0;

void _linux_lib_string_sym_match()
{
    kfunc_match(strncasecmp, name, addr);
    kfunc_match(strcasecmp, name, addr);
    kfunc_match(strcpy, name, addr);
    kfunc_match(strncpy, name, addr);
    // kfunc_match(strlcpy, name, addr);
    // kfunc_match(strscpy, name, addr);
    // kfunc_match(strscpy_pad, name, addr);
    kfunc_match(stpcpy, name, addr);
    kfunc_match(strcat, name, addr);
    kfunc_match(strncat, name, addr);
    kfunc_match(strlcat, name, addr);
    kfunc_match(strcmp, name, addr);
    kfunc_match(strncmp, name, addr);
    // kfunc_match(strchr, name, addr);
    // kfunc_match(strchrnul, name, addr);
    // kfunc_match(strnchrnul, name, addr);
    // kfunc_match(strrchr, name, addr);
    // kfunc_match(strnchr, name, addr);
    // kfunc_match(skip_spaces, name, addr);
    // kfunc_match(strim, name, addr);
    kfunc_match(strlen, name, addr);
    kfunc_match(strnlen, name, addr);
    // kfunc_match(strspn, name, addr);
    // kfunc_match(strcspn, name, addr);
    // kfunc_match(strpbrk, name, addr);
    // kfunc_match(strsep, name, addr);
    // kfunc_match(sysfs_streq, name, addr);
    // kfunc_match(match_string, name, addr);
    // kfunc_match(__sysfs_match_string, name, addr);
    kfunc_match(memset, name, addr);
    // kfunc_match(memset16, name, addr);
    // kfunc_match(memset32, name, addr);
    // kfunc_match(memset64, name, addr);
    kfunc_match(memcpy, name, addr);
    kfunc_match(memmove, name, addr);
    kfunc_match(memcmp, name, addr);
    // kfunc_match(bcmp, name, addr);
    // kfunc_match(memscan, name, addr);
    // kfunc_match(strstr, name, addr);
    // kfunc_match(strnstr, name, addr);
    // kfunc_match(memchr, name, addr);
    // kfunc_match(memchr_inv, name, addr);
    // kfunc_match(strreplace, name, addr);
    // kfunc_match(fortify_panic, name, addr);
}

// lib/strncpy_from_user.c
#include <linux/uaccess.h>

long kfunc_def(strncpy_from_user)(char *dst, const char __user *src, long count) = 0;

void _linux_lib_strncpy_from_user_sym_match()
{
    kfunc_match(strncpy_from_user, name, addr);
}

// lib/strnlen_user.c
#include <linux/uaccess.h>

long kfunc_def(strnlen_user)(const char __user *str, long count) = 0;

void _linxu_lib_strnlen_user_sym_match()
{
    kfunc_match(strnlen_user, name, addr);
}

// mm/util.c
struct file;
struct page;
struct address_space;
struct task_struct;

void kfunc_def(kfree_const)(const void *x) = 0;
char *kfunc_def(kstrdup)(const char *s, gfp_t gfp) = 0;
const char *kfunc_def(kstrdup_const)(const char *s, gfp_t gfp) = 0;
char *kfunc_def(kstrndup)(const char *s, size_t max, gfp_t gfp) = 0;
void *kfunc_def(kmemdup)(const void *src, size_t len, gfp_t gfp) = 0;
char *kfunc_def(kmemdup_nul)(const char *s, size_t len, gfp_t gfp) = 0;
void *kfunc_def(memdup_user)(const void __user *src, size_t len) = 0;
void *kfunc_def(vmemdup_user)(const void __user *src, size_t len) = 0;
char *kfunc_def(strndup_user)(const char __user *s, long n) = 0;
void *kfunc_def(memdup_user_nul)(const void __user *src, size_t len) = 0;
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

void _linux_mm_utils_sym_match()
{
    // kfunc_match(kfree_const, name, addr);
    kfunc_match(kstrdup, name, addr);
    // kfunc_match(kstrdup_const, name, addr);
    kfunc_match(kstrndup, name, addr);
    kfunc_match(kmemdup, name, addr);
    kfunc_match(kmemdup_nul, name, addr);
    kfunc_match(memdup_user, name, addr);
    kfunc_match(vmemdup_user, name, addr);
    kfunc_match(strndup_user, name, addr);
    kfunc_match(memdup_user_nul, name, addr);
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
}

// lib/dump_stack.c
void kfunc_def(dump_stack_lvl)(const char *log_lvl) = 0;
void kfunc_def(dump_stack)(void) = 0;

void _linux_lib_dump_stack_sym_match()
{
    // kfunc_match(dump_stack_lvl, name, addr);
    // kfunc_match(dump_stack, name, addr);
}

// mm/vmalloc.c
#include <linux/vmalloc.h>

void kfunc_def(vm_unmap_ram)(const void *mem, unsigned int count) = 0;
void *kfunc_def(vm_map_ram)(struct page **pages, unsigned int count, int node) = 0;
void kfunc_def(vm_unmap_aliases)(void) = 0;

void *kfunc_def(vmalloc)(unsigned long size) = 0;
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

void _linux_mm_vmalloc_sym_match()
{
    // kfunc_match(vm_unmap_ram, name, addr);
    // kfunc_match(vm_map_ram, name, addr);
    // kfunc_match(vm_unmap_aliases, name, addr);

    kfunc_match(vmalloc, name, addr);
    kfunc_match(vzalloc, name, addr);
    kfunc_match(vmalloc_user, name, addr);
    // kfunc_match(vmalloc_node, name, addr);
    // kfunc_match(vzalloc_node, name, addr);
    // kfunc_match(vmalloc_32, name, addr);
    // kfunc_match(vmalloc_32_user, name, addr);
    kfunc_match(__vmalloc, name, addr);
    // kfunc_match(__vmalloc_node_range, name, addr);
    // kfunc_match(__vmalloc_node, name, addr);

    kfunc_match(vfree, name, addr);
    kfunc_match(vfree_atomic, name, addr);

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

//