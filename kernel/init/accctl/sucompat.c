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
#include <accctl.h>

#define INVALID_ALLOW_UID ((uid_t)-1)

static const char android_su_path[] = "/system/bin/ab";
static const char android_sh_path[] = "/system/bin/sh";

static uid_t su_allow_list[32];

static inline int is_su_allow(uid_t uid)
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
static inline uid_t current_uid()
{
    struct cred *cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    return *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
}

static void *__user copy_to_user_stack(void *data, size_t len)
{
    uintptr_t addr = current_user_stack_pointer() - len;
    addr = addr & ~0xfl;
    if (!kfunc(seq_buf_to_user)) {
        addr = trace_seq_copy_to_user((void *__user)addr, data, len) ? addr : 0;
    } else {
        addr = seq_buf_copy_to_user((void *__user)addr, data, len) ? addr : 0;
    }
    return (void *)addr;
}

static inline char *__user android_sh_user_path()
{
    return (char *__user)copy_to_user_stack((void *)android_sh_path, sizeof(android_sh_path));
}

struct file;
struct kstat;

#if 1
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

static void handle_do_execv(char *filename)
{
    if (is_su_allow(current_uid())) {
        if (!min_strcmp(filename, android_su_path)) {
            logkd("execv: %s\n", filename);
            // todo: sctx
            commit_su(0, 0);
            min_strcpy((void *)filename, android_sh_path);
        }
    }
}

// int do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
// int __do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags,
//                      struct file *file);

static void *(*backup_do_execve)(int fd, struct filename *filename, void *argv1, void *argv2, void *envp1, void *envp2,
                                 void *flags, struct file *file) = 0;
static void *replace_do_execve(int fd, struct filename *filename, void *argv1, void *argv2, void *envp1, void *envp2,
                               void *flags, struct file *file)
{
    handle_do_execv((char *)filename->name);
    void *rc = backup_do_execve(fd, filename, argv1, argv2, envp1, envp2, flags, file);
    return rc;
}

// static int do_execve(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp);
static void *(*backup_do_execv_legacy)(struct filename *filename, void *argv1, void *argv2, void *envp1,
                                       void *envp2) = 0;
// lower version
static void *replace_do_execv_legacy(struct filename *filename, void *argv1, void *argv2, void *envp1, void *envp2)
{
    handle_do_execv((char *)filename->name);
    void *rc = backup_do_execv_legacy(filename, argv1, argv2, envp1, envp2);
    return rc;
}

static void handle_accessat(char **__user filename)
{
    if (is_su_allow(current_uid())) {
        char buf[sizeof(android_su_path)] = { '\0' };
        strncpy_from_user(buf, *filename, sizeof(android_su_path) - 1);
        if (!min_strcmp(buf, android_su_path)) {
            *filename = android_sh_user_path();
        }
    }
}

// long do_faccessat(int dfd, const char __user *filename, int mode, int flags)
// SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
static long (*backup_faccessat)(int dfd, char __user *filename, int mode, int flag) = 0;
static long replace_faccessat(int dfd, char __user *filename, int mode, int flag)
{
    log_user_string("faccessat before", filename);
    handle_accessat(&filename);
    int rc = backup_faccessat(dfd, filename, mode, flag);
    log_user_string("faccessat after", filename);
    return rc;
}

static void handle_stat(char **__user filename)
{
    if (is_su_allow(current_uid())) {
        char buf[sizeof(android_su_path)] = { '\0' };
        strncpy_from_user(buf, *filename, sizeof(android_su_path) - 1);
        if (!min_strcmp(buf, android_su_path)) {
            *filename = android_sh_user_path();
        }
    }
}

static int (*backup_vfs_fstatat)(int dfd, char __user *filename, struct kstat *stat, int flags) = 0;
static int replace_vfs_fstatat(int dfd, char __user *filename, struct kstat *stat, int flags)
{
    log_user_string("fstate before", filename);
    handle_stat(&filename);
    int ret = backup_vfs_fstatat(dfd, filename, stat, flags);
    log_user_string("fstate after", filename);
    return ret;
}

static int (*backup_vfs_statx)(int dfd, char __user *filename, int flags, struct kstat *stat, u32 request_mask) = 0;
static int replace_vfs_statx(int dfd, char __user *filename, int flags, struct kstat *stat, u32 request_mask)
{
    log_user_string("statx before", filename);
    handle_stat(&filename);
    int ret = backup_vfs_statx(dfd, filename, flags, stat, request_mask);
    log_user_string("statx after", filename);
    return ret;
}

int su_compat_init()
{
    for (int i = 0; i < SUPERCALL_SU_ALLOW_MAX; i++) {
        su_allow_list[i] = INVALID_ALLOW_UID;
    }

    // execv
    unsigned long execve_addr = kallsyms_lookup_name("__do_execve_file");
    if (!execve_addr)
        execve_addr = kallsyms_lookup_name("do_execveat_common");

    if (execve_addr) {
        hook_err_t err = hook((void *)execve_addr, (void *)replace_do_execve, (void **)&backup_do_execve);
        if (err) {
            logke("hook execve error: %d\n", err);
            return err;
        }
    } else {
        execve_addr = kallsyms_lookup_name("do_execve");
        if (!execve_addr) {
            logke("Can't find do_execv\n");
            return ERR_NO_SUCH_SYMBOL;
        }
        hook_err_t err = hook((void *)execve_addr, (void *)replace_do_execv_legacy, (void **)&backup_do_execv_legacy);
        if (err) {
            logke("hook execve error: %d\n", err);
            return err;
        }
    }

    // faccessat
    unsigned long faccessat_addr = kallsyms_lookup_name("do_faccessat");
    if (!faccessat_addr) {
        logkw("Can't find symbol do_faccessat\n");
        // todo: wrap hook syscall
        faccessat_addr = kallsyms_lookup_name("sys_faccessat");
    }
    if (!faccessat_addr) {
        logke("Can't find symbol sys_faccessat\n");
        return ERR_NO_SUCH_SYMBOL;
    }
    hook_err_t err = hook((void *)faccessat_addr, (void *)replace_faccessat, (void **)&backup_faccessat);
    if (err) {
        logke("hook do_faccessat error: %d\n", err);
        return err;
    }

    // fstate
    unsigned long vfs_fstatx_addr = kallsyms_lookup_name("vfs_statx");
    if (vfs_fstatx_addr) {
        err = hook((void *)vfs_fstatx_addr, (void *)replace_vfs_statx, (void **)&backup_vfs_statx);
        if (err) {
            logke("hook vfs_fstatat error: %d\n", err);
            return err;
        }
    } else {
        logkw("Can't find symbol vfs_statx, use vfs_fstatat instead\n");
        unsigned long vfs_fstatat_addr = kallsyms_lookup_name("vfs_fstatat");
        if (vfs_fstatat_addr) {
            err = hook((void *)vfs_fstatat_addr, (void *)replace_vfs_fstatat, (void **)&backup_vfs_fstatat);
            if (err) {
                logke("hook vfs_fstatat error: %d\n", err);
                return err;
            }
        } else {
            logke("Can't find symbol vfs_statx\n");
            return ERR_NO_SUCH_SYMBOL;
        }
    }

    return 0;
}