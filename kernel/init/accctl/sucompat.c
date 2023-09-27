#include <linux/list.h>
#include <ktypes.h>
#include <stdbool.h>
#include <linux/vmalloc.h>
#include <syscall.h>
#include <ksyms.h>
#include <hook.h>
#include <error.h>
#include <minc/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <linux/seq_buf.h>
#include <linux/trace_seq.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <accctl.h>
#include <linux/err.h>

#define INVALID_ALLOW_UID ((uid_t)-1)

// sizeof android_su_path must not bigger than sizeof android_sh_path
static const char android_su_path[] = "/system/bin/sc";
static const char android_sh_path[] = "/system/bin/sh";

static uid_t su_allow_list[32];

static int is_su_allow(uid_t uid)
{
    for (int i = 0; i < SUPERCALL_SU_ALLOW_MAX; i++) {
        if (su_allow_list[i] == uid)
            return 1;
    }
    return 0;
}

int add_allow_uid(uid_t uid)
{
    for (int i = 0; i < SUPERCALL_SU_ALLOW_MAX; i++) {
        if (su_allow_list[i] == INVALID_ALLOW_UID || su_allow_list[i] == uid) {
            su_allow_list[i] = uid;
            return 0;
        }
    }
    return ERR_CAP_FULL;
}

int remove_allow_uid(uid_t uid)
{
    for (int i = 0; i < SUPERCALL_SU_ALLOW_MAX; i++) {
        if (su_allow_list[i] == uid) {
            su_allow_list[i] = INVALID_ALLOW_UID;
        }
    }
    return ERR_NO_SUCH_ID;
}

// todo: PAGE_SIZE
static int list_allow_uids_compat(uid_t __user *uids, size_t __user *size)
{
    // uids
    struct trace_seq trace_seq;
    trace_seq_init(&trace_seq);
    size_t num = 0;
    for (int i = 0; i < SUPERCALL_SU_ALLOW_MAX; i++) {
        uid_t uid = su_allow_list[i];
        if (uid != INVALID_ALLOW_UID) {
            trace_seq_putmem(&trace_seq, &uid, sizeof(uid_t));
            num++;
        }
    }
    trace_seq_to_user(&trace_seq, (char *)uids, num * sizeof(uid_t));
    // size
    trace_seq_init(&trace_seq);
    trace_seq_putmem(&trace_seq, (void *)&num, sizeof(num));
    trace_seq_to_user(&trace_seq, (char *)size, sizeof(size_t));
    return ERR_NO_ERR;
}

int list_allow_uids(uid_t __user *uids, size_t __user *size)
{
    if (!kfunc(seq_buf_to_user)) {
        return list_allow_uids_compat(uids, size);
    }
    // uids
    struct seq_buf seq_buf;
    seq_buf_clear(&seq_buf);
    char buffer[SUPERCALL_SU_ALLOW_MAX * sizeof(uid_t)];
    seq_buf.buffer = buffer;
    seq_buf.size = sizeof(seq_buf);
    size_t num = 0;
    for (int i = 0; i < SUPERCALL_SU_ALLOW_MAX; i++) {
        uid_t uid = su_allow_list[i];
        if (uid != INVALID_ALLOW_UID) {
            ((uid_t *)buffer)[num++] = uid;
            seq_buf.len = num * sizeof(uid_t);
        }
    }
    int rc = 0;
    if (num > 0) {
        rc = seq_buf_to_user(&seq_buf, (char *)uids, seq_buf.len);
        if (rc != seq_buf.len) {
            logkfe("copy to user uid error\n");
            return ERR_COPY_TO_USER;
        }
    }

    // size
    seq_buf_clear(&seq_buf);
    *(size_t *)buffer = num;
    seq_buf.len = sizeof(size_t);
    rc = seq_buf_to_user(&seq_buf, (char *)size, seq_buf.len);
    if (rc != sizeof(size_t)) {
        logkfe("copy to user uid error\n");
        return ERR_COPY_TO_USER;
    }
    return ERR_NO_ERR;
}

// todo: rcu_dereference_protected
static __noinline uid_t current_uid()
{
    struct cred *cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
    return uid;
}

// todo: KernelSU idea, but not stable ?
static void *__user copy_to_user_stack(void *data, size_t len)
{
    uintptr_t addr = current_user_stack_pointer();
    addr -= len;
    addr &= 0xFFFFFFFFFFFFFFF0;
    // sometimes, to avoid userspace -fstack-protector
    addr -= 0x10;
    copy_to_user((void *)addr, data, len);
    return (void *)addr;
}

static inline char *__user android_sh_user_path()
{
    return (char *__user)copy_to_user_stack((void *)android_sh_path, sizeof(android_sh_path));
}

struct file;
struct kstat;

#if 0
static void log_user_string(const char *tag, const char *__user ustring)
{
    if (is_su_allow(current_uid())) {
        char buf[64] = { '\0' };
        strncpy_from_user(buf, ustring, 63);
        logkd("tag: %s, ustring: %s\n", tag, buf);
    }
}
#else
static inline void log_user_string(const char *tag, const char *__user filename)
{
}
#endif

// int do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
// int __do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags,
//                      struct file *file);
// 3.18: static int do_execve(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp);
static void *(*backup_do_execve)(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7) = 0;
static void *replace_do_execve(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    volatile uid_t uid = current_uid();
    if (is_su_allow(uid)) {
        struct filename *filename;
        if ((((uintptr_t)a0) & 0xF000000000000000) == 0xF000000000000000) {
            filename = (struct filename *)a0;
        } else {
            filename = (struct filename *)a1;
        }
        if (!IS_ERR(filename)) {
            if (!min_strcmp(filename->name, android_su_path)) {
                // todo: bugs printk
                // logkd("exec: uid: %d, filename: %s\n", uid, filename->name);
                commit_su(0, 0);
                min_strcpy((char *)filename->name, android_sh_path);
            }
        }
    }
    void *rc = backup_do_execve(a0, a1, a2, a3, a4, a5, a6, a7);
    return rc;
}

// long do_faccessat(int dfd, const char __user *filename, int mode, int flags)
// SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
static long (*backup_faccessat)(int dfd, char __user *filename, int mode, int flag) = 0;
static long replace_faccessat(int dfd, char __user *filename, int mode, int flag)
{
    int change_flag = 0;
    volatile uid_t uid = current_uid();
    if (is_su_allow(uid)) {
        char buf[sizeof(android_su_path) + 1] = { '\0' };
        strncpy_from_user(buf, filename, sizeof(android_su_path));
        if (!min_strcmp(buf, android_su_path)) {
            logkd("access: uid: %d, filename: %s\n", uid, buf);
            copy_to_user(filename, android_sh_path, sizeof(android_sh_path));
            change_flag = 1;
        }
    }
    int rc = backup_faccessat(dfd, filename, mode, flag);
    if (change_flag) {
        copy_to_user(filename, (void *)android_su_path, sizeof(android_su_path));
    }
    return rc;
}

// int vfs_statx(int dfd, struct filename *filename, int flags, struct kstat *stat, u32 request_mask)
// int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
// int do_statx(int dfd, struct filename *filename, unsigned int flags, unsigned int mask, struct statx __user *buffer)
// int vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
static void *(*backup_vfs_stat)(int dfd, void *a1, void *a2, void *a3, void *a4, void *a5) = 0;
static void *replace_vfs_stat(int dfd, void *a1, void *a2, void *a3, void *a4, void *a5)
{
    int change_flag = 0;
    volatile uid_t uid = current_uid();
    if (is_su_allow(uid)) {
        if ((((uintptr_t)a1) & 0xF000000000000000) == 0xF000000000000000) {
            struct filename *filename = (struct filename *)a1;
            if (!min_strcmp(filename->name, android_su_path)) {
                logkd("stat: uid: %d, filename: %s\n", uid, filename);
                min_strcpy((char *)filename->name, android_sh_path);
            }
        } else {
            char buf[sizeof(android_su_path) + 1] = { '\0' };
            strncpy_from_user(buf, a1, sizeof(android_su_path));
            if (!min_strcmp(buf, android_su_path)) {
                logkd("stat: uid: %d, user filename: %s\n", uid, buf);
                copy_to_user(a1, android_sh_path, sizeof(android_sh_path));
                change_flag = 1;
            }
        }
    }
    void *ret = backup_vfs_stat(dfd, a1, a2, a3, a4, a5);
    if (change_flag) {
        copy_to_user(a1, (void *)android_su_path, sizeof(android_su_path));
    }
    return ret;
}

static int hook_execv_compat(void *data, const char *name, struct module *, unsigned long addr)
{
    if (min_strncmp("do_execve_common", name, min_strlen("do_execve_common"))) {
        return 0;
    }
    logkd("Find do_execve_common symbol: %s\n", name);
    hook_err_t err = hook((void *)addr, (void *)replace_do_execve, (void **)&backup_do_execve);
    if (err) {
        logke("Hook %s error: %d\n", name, err);
        return err;
    }
    return 1;
}

int su_compat_init()
{
    for (int i = 0; i < SUPERCALL_SU_ALLOW_MAX; i++) {
        su_allow_list[i] = INVALID_ALLOW_UID;
    }
    hook_err_t err = HOOK_NO_ERR;

    // state
    unsigned long vfs_stat_addr = kallsyms_lookup_name("vfs_statx");
    if (!vfs_stat_addr) {
        vfs_stat_addr = kallsyms_lookup_name("do_statx");
    }
    if (!vfs_stat_addr) {
        vfs_stat_addr = kallsyms_lookup_name("vfs_fstatat");
    }
    if (!vfs_stat_addr) {
        logke("Can't find symbol vfs_fstatat, do_statx or vfs_statx\n");
        return ERR_NO_SUCH_SYMBOL;
    }
    err = hook((void *)vfs_stat_addr, (void *)replace_vfs_stat, (void **)&backup_vfs_stat);
    if (err) {
        logke("Hook vfs_fstatat error: %d\n", err);
        return err;
    }

    // access
    unsigned long faccessat_addr = kallsyms_lookup_name("do_faccessat");
    if (!faccessat_addr) {
        faccessat_addr = kallsyms_lookup_name("sys_faccessat");
    }
    if (!faccessat_addr) {
        logke("Can't find symbol do_faccessat or sys_faccessat\n");
        return ERR_NO_SUCH_SYMBOL;
    }
    err = hook((void *)faccessat_addr, (void *)replace_faccessat, (void **)&backup_faccessat);
    if (err) {
        logke("Hook do_faccessat error: %d\n", err);
        return err;
    }

    // execv
    unsigned long execve_addr = kallsyms_lookup_name("__do_execve_file");
    if (!execve_addr)
        execve_addr = kallsyms_lookup_name("do_execveat_common");
    if (!execve_addr) {
        kallsyms_on_each_symbol(hook_execv_compat, 0);
    } else {
        err = hook((void *)execve_addr, (void *)replace_do_execve, (void **)&backup_do_execve);
        if (err) {
            logke("Hook __do_execve_file or do_execveat_common error: %d\n", err);
            return err;
        }
    }

    return 0;
}