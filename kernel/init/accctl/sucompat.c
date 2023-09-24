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

#define INVALID_ALLOW_UID ((uid_t)-1)

static const char android_su_path[] = "/system/bin/su";
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
    logkfd("uid: %d\n", uid);
    for (int i = 0; i < SUPERCALL_SU_ALLOW_MAX; i++) {
        if (su_allow_list[i] == INVALID_ALLOW_UID || su_allow_list[i] == uid) {
            su_allow_list[i] = uid;
            logkfd("uid: %d\n", uid);
            return 0;
        }
    }
    return ERR_CAP_FULL;
}

int remove_allow_uid(uid_t uid)
{
    logkfd("uid: %d\n", uid);
    for (int i = 0; i < SUPERCALL_SU_ALLOW_MAX; i++) {
        if (su_allow_list[i] == uid) {
            su_allow_list[i] = INVALID_ALLOW_UID;
            logkfd("uid: %d\n", uid);
        }
    }
    return ERR_NO_SUCH_ID;
}

int list_allow_uids(uid_t *uids, int *size)
{
    struct seq_buf buf;
    seq_buf_clear(&buf);
    buf.buffer = "abcdef\n";
    buf.len = 8;
    logkfd("xxxxxx: %llx\n", uids);
    int rc = seq_buf_to_user(&buf, uids, 8);
    logkfd("xxxxxx rc  %llx\n", rc);

    // for (int i = 0; i < SUPERCALL_SU_ALLOW_MAX; i++) {
    //     uid_t uid = su_allow_list[i];
    //     if (uid != INVALID_ALLOW_UID) {
    //         logkfd("uid: %d\n", uid);
    //     }
    // }
    return ERR_NO_ERR;
}

// todo: rcu_dereference_protected
static inline uid_t current_uid()
{
    struct cred *cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    return *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
}

struct file;
struct kstat;

// int do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
// int __do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags,
//                      struct file *file);
static void *(*backup_do_execve)(int fd, struct filename *filename, void *argv1, void *argv2, void *envp1, void *envp2,
                                 void *flags, struct file *file) = 0;
static void *replace_do_execve(int fd, struct filename *filename, void *argv1, void *argv2, void *envp1, void *envp2,
                               void *flags, struct file *file)
{
    if (is_su_allow(current_uid())) {
        logkfd("filename: %s %s\n", filename->name, filename->iname);
    }
    void *rc = backup_do_execve(fd, filename, argv1, argv2, envp1, envp2, flags, file);
    return rc;
}

// long do_faccessat(int dfd, const char __user *filename, int mode, int flags)
// SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
static long (*backup_faccessat)(int dfd, const char __user *filename, int mode, int flag) = 0;
static long replace_faccessat(int dfd, const char __user *filename, int mode, int flag)
{
    if (is_su_allow(current_uid())) {
        char buf[64] = { '\0' };
        strncpy_from_user(buf, filename, 63);
        logkfd("filename: %s\n", buf);
    }
    int rc = backup_faccessat(dfd, filename, mode, flag);
    return rc;
}

static int (*backup_vfs_fstatat)(int dfd, const char __user *filename, struct kstat *stat, int flags) = 0;
static int replace_vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
{
    if (is_su_allow(current_uid())) {
        char buf[64] = { '\0' };
        strncpy_from_user(buf, filename, 63);
        logkfd("filename: %s\n", buf);
    }
    int ret = backup_vfs_fstatat(dfd, filename, stat, flags);
    return ret;
}

static int (*backup_vfs_statx)(int dfd, const char __user *filename, int flags, struct kstat *stat,
                               u32 request_mask) = 0;
static int replace_vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
{
    if (is_su_allow(current_uid())) {
        char buf[64] = { '\0' };
        strncpy_from_user(buf, filename, 63);
        logkfd("filename: %s\n", buf);
    }
    int ret = backup_vfs_statx(dfd, filename, flags, stat, request_mask);
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
    if (!execve_addr) {
        logke("Can't find symbol __do_execve_file or do_execveat_common\n");
    }
    hook_err_t err = hook((void *)execve_addr, (void *)replace_do_execve, (void **)&backup_do_execve);
    if (err) {
        logke("hook execve error: %d\n", err);
        return err;
    }

    // faccessat
    unsigned long faccessat_addr = kallsyms_lookup_name("do_faccessat");
    faccessat_addr = 0;
    if (!faccessat_addr) {
        logkw("Can't find symbol do_faccessat\n");
        // todo: wrap hook syscall
        faccessat_addr = kallsyms_lookup_name("sys_faccessat");
    }
    if (!faccessat_addr) {
        logke("Can't find symbol sys_faccessat\n");
        return ERR_NO_SUCH_SYMBOL;
    }
    err = hook((void *)faccessat_addr, (void *)replace_faccessat, (void **)&backup_faccessat);
    if (err) {
        logke("hook do_faccessat error: %d\n", err);
        return err;
    }

    // fstate
    unsigned long vfs_fstatx_addr = kallsyms_lookup_name("vfs_statx");
    vfs_fstatx_addr = 0;
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
            logke("hook vfs_fstatat error: %d\n", err);
            return err;
        } else {
            logke("Can't find symbol vfs_statx\n");
            return ERR_NO_SUCH_SYMBOL;
        }
    }

    return 0;
}