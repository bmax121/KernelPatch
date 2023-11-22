#include <linux/list.h>
#include <ktypes.h>
#include <stdbool.h>
#include <linux/vmalloc.h>
#include <linux/syscall.h>
#include <ksyms.h>
#include <hook.h>
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
#include <kputils.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <taskob.h>

/*
Copy and modified from KernelSU, GPLv2
https://github.com/tiann/KernelSU
*/

#define INVALID_ALLOW_UID ((uid_t)-1)

static char android_su_path[] = "/system/bin/kp";
static const char android_sh_path[] = "/system/bin/sh";

static uid_t su_allow_list[32];

static int is_su_allow(uid_t uid)
{
    for (int i = 0; i < SUPERCALL_SU_ALLOW_UID_MAX; i++) {
        if (su_allow_list[i] == uid) return 1;
    }
    return 0;
}

int su_add_allow_uid(uid_t uid)
{
    for (int i = 0; i < SUPERCALL_SU_ALLOW_UID_MAX; i++) {
        if (su_allow_list[i] == INVALID_ALLOW_UID || su_allow_list[i] == uid) {
            su_allow_list[i] = uid;
            return 0;
        }
    }
    return -ENOMEM;
}

int su_remove_allow_uid(uid_t uid)
{
    for (int i = 0; i < SUPERCALL_SU_ALLOW_UID_MAX; i++) {
        if (su_allow_list[i] == uid) {
            su_allow_list[i] = INVALID_ALLOW_UID;
        }
    }
    return 0;
}

int su_allow_uid_nums()
{
    int num = 0;
    for (int i = 0; i < SUPERCALL_SU_ALLOW_UID_MAX; i++) {
        uid_t uid = su_allow_list[i];
        if (uid != INVALID_ALLOW_UID) {
            num++;
        }
    }
    return num;
}

int su_list_allow_uids(uid_t __user *uids, int num)
{
    uid_t buf[SUPERCALL_SU_ALLOW_UID_MAX];
    int bufi = 0;

    for (int i = 0; i < SUPERCALL_SU_ALLOW_UID_MAX; i++) {
        uid_t uid = su_allow_list[i];
        if (uid != INVALID_ALLOW_UID) {
            buf[bufi++] = uid;
        }
    }

    int max_num = num < bufi ? num : bufi;

    int len = seq_copy_to_user(uids, buf, max_num * sizeof(uid_t));
    if (len != max_num * sizeof(uid_t)) {
        logke("su allow to user error: %d\n", len);
        return len;
    }

    return bufi;
}

// todo:
int su_reset_path(const char *cmd)
{
    if (strnlen(cmd, sizeof(android_su_path)) >= sizeof(android_su_path)) {
        return -ENOMEM;
    }
    strlcpy(android_su_path, cmd, sizeof(android_su_path));
    dsb(ishst);
    logki("reset su to: %s\n", cmd);
    return 0;
}

int su_get_path(char *__user cmd, int arg2)
{
    int len = strnlen(android_su_path, sizeof(android_su_path));
    if (arg2 <= len) return -ENOMEM;
    return seq_copy_to_user(cmd, android_su_path, len);
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
    addr -= 10;
    seq_copy_to_user((void *)addr, data, len);
    return (void *)addr;
}

static inline char *__user android_sh_user_path()
{
    return (char *__user)copy_to_user_stack((void *)android_sh_path, sizeof(android_sh_path));
}

static inline char *__user android_su_user_path()
{
    return (char *__user)copy_to_user_stack((void *)android_su_path, min_strlen(android_su_path) + 1);
}

struct file;
struct kstat;

#if 0
static void log_user_string(const char *tag, const char *__user ustring)
{
    if (is_su_allow(current_uid())) {
        char buf[64] = { '\0' };
        strncpy_from_user_nofault(buf, ustring, 64);
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
// static int do_execve_common(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp)
void before_do_execve(hook_fargs8_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (!is_su_allow(uid)) return;
    struct filename *filename;
    if ((((uintptr_t)args->arg0) & 0xF000000000000000) == 0xF000000000000000) {
        filename = (struct filename *)args->arg0;
    } else {
        filename = (struct filename *)args->arg1;
    }
    // logkd("exec su uid: %d, %s\n", uid, filename->name);
    if (filename && !IS_ERR(filename)) {
        if (!strcmp(filename->name, android_su_path)) {
            logkd("su exec uid: %d\n", uid);
            commit_su(0, 0);
            min_strcpy((char *)filename->name, android_sh_path);
        }
    }
}

// long do_faccessat(int dfd, const char __user *filename, int mode, int flags)
// SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
void before_faccessat(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (!is_su_allow(uid)) return;

    char __user *filename = (char __user *)args->arg1;
    char buf[sizeof(android_su_path)] = { '\0' };
    strncpy_from_user_nofault(buf, filename, sizeof(android_su_path));

    if (!strcmp(buf, android_su_path)) {
        logkd("su access uid: %d\n", uid);
        args->ret = 0;
        args->early_ret = 1;
    }
}

// int vfs_statx(int dfd, struct filename *filename, int flags, struct kstat *stat, u32 request_mask)
// int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
// int do_statx(int dfd, struct filename *filename, unsigned int flags, unsigned int mask, struct statx __user *buffer)
// int do_statx(int dfd, const char __user *filename, unsigned flags, unsigned int mask, struct statx __user *buffer)
// int vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
void before_stat(hook_fargs8_t *args, void *udata)
{
    int change_flag = 0;
    args->local.data[0] = change_flag;

    uid_t uid = current_uid();
    if (!is_su_allow(uid)) return;

    if ((((uintptr_t)args->arg1) & 0xF000000000000000) == 0xF000000000000000) {
        struct filename *filename = (struct filename *)args->arg1;
        if (!strcmp(filename->name, android_su_path)) {
            logkd("su stat0 uid: %d\n", uid);
            min_strcpy((char *)filename->name, android_sh_path);
        }
    } else {
        char buf[sizeof(android_su_path)] = { '\0' };
        strncpy_from_user_nofault(buf, (char *)args->arg1, sizeof(android_su_path));
        if (!strcmp(buf, android_su_path)) {
            logkd("su stat1 uid: %d\n", uid);
            int sz = seq_copy_to_user((void *)args->arg1, android_sh_path, sizeof(android_sh_path));
            if (sz != sizeof(android_sh_path)) {
                logke("seq_copy_to_user error: %d\n", sz);
            }
            change_flag = 1;
        }
    }
    args->local.data[0] = change_flag;
}

void after_stat(hook_fargs8_t *args, void *udata)
{
    int change_flag = args->local.data[0];
    if (change_flag) {
        int len = min_strlen(android_su_path) + 1;
        int sz = seq_copy_to_user((void *)args->arg1, android_su_path, len);
        if (sz != len) {
            logke("seq_copy_to_user error: %d\n", sz);
        }
    }
}

int su_compat_init()
{
    int rc = 0;

    for (int i = 0; i < SUPERCALL_SU_ALLOW_UID_MAX; i++) {
        su_allow_list[i] = INVALID_ALLOW_UID;
    }
    // todo:
    su_allow_list[0] = 2000;

    // state
    unsigned long vfs_stat_addr = kallsyms_lookup_name("vfs_statx");
    if (!vfs_stat_addr) {
        vfs_stat_addr = kallsyms_lookup_name("do_statx");
    }
    if (!vfs_stat_addr) {
        vfs_stat_addr = kallsyms_lookup_name("vfs_fstatat");
    }
    if (!vfs_stat_addr) {
        log_boot("no symbol vfs_fstatat, do_statx or vfs_statx\n");
        rc = -ENOENT;
        goto out;
    } else {
        hook_err_t err = hook_wrap8((void *)vfs_stat_addr, before_stat, after_stat, 0);
        if (err) {
            log_boot("hook vfs_fstatat error: %d\n", err);
            rc = err;
            goto out;
        }
    }

    // access
    unsigned long faccessat_addr = kallsyms_lookup_name("do_faccessat");
    if (!faccessat_addr) {
        faccessat_addr = kallsyms_lookup_name("sys_faccessat");
    }
    if (!faccessat_addr) {
        log_boot("no symbol do_faccessat or sys_faccessat\n");
        rc = -ENOENT;
        goto out;
    } else {
        hook_err_t err = hook_wrap4((void *)faccessat_addr, before_faccessat, 0, 0);
        if (err) {
            log_boot("hook do_faccessat error: %d\n", err);
            rc = err;
            goto out;
        }
    }

    // execv
    hook_err_t err = add_execv_hook(before_do_execve, 0, 0);
    if (err) {
        log_boot("hook add execv error: %d\n", err);
        rc = err;
        goto out;
    }

out:
    return rc;
}