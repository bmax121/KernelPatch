#include <linux/list.h>
#include <ktypes.h>
#include <stdbool.h>
#include <linux/syscall.h>
#include <ksyms.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <taskob.h>
#include <linux/ptrace.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <syscall.h>
#include <predata.h>
#include <uapi/scdefs.h>

/*
Modified from KernelSU, GPLv2
https://github.com/tiann/KernelSU
*/

static const char sh_path[] = ANDROID_SH_PATH;
static const char su_path[SU_PATH_MAX_LEN] = ANDROID_SU_PATH;
static const char *current_su_path = 0;
static const char apd_path[] = APD_PATH;
static const char kpatch_path[] = KPATCH_PATH;
static const char kpatch_shadow_path[] = KPATCH_SHADOW_PATH;

struct allow_uid
{
    uid_t uid;
    struct su_profile profile;
    struct list_head list;
    struct rcu_head rcu;
};

static struct list_head allow_uid_list;
static spinlock_t list_lock;

static void allow_reclaim_callback(struct rcu_head *rcu)
{
    struct allow_uid *allow = container_of(rcu, struct allow_uid, rcu);
    kfree(allow);
}

static struct su_profile *search_allow_uid(uid_t uid)
{
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry_rcu(pos, &allow_uid_list, list)
    {
        if (pos->uid == uid) {
            // make a deep copy
            struct su_profile *profile = kmalloc(sizeof(struct su_profile), GFP_ATOMIC);
            memcpy(profile, &pos->profile, sizeof(struct su_profile));
            rcu_read_unlock();
            return profile;
        }
    }
    rcu_read_unlock();
    return 0;
}

static int is_allow_uid(uid_t uid)
{
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry_rcu(pos, &allow_uid_list, list)
    {
        if (pos->uid == uid) {
            rcu_read_unlock();
            return 1;
        }
    }
    rcu_read_unlock();
    return 0;
}

int su_add_allow_uid(uid_t uid, struct su_profile *profile, int async)
{
    rcu_read_lock();
    struct allow_uid *pos, *old = 0;
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        if (pos->uid == uid) {
            old = pos;
            break;
        }
    }
    struct allow_uid *new = (struct allow_uid *)kmalloc(sizeof(struct allow_uid), GFP_ATOMIC);
    new->uid = profile->uid;
    memcpy(&new->profile, profile, sizeof(struct su_profile));
    new->profile.scontext[sizeof(new->profile.scontext) - 1] = '\0';

    spin_lock(&list_lock);
    if (old) { // update
        list_replace_rcu(&old->list, &new->list);
        logkfi("update uid: %d, to_uid: %d, sctx: %s\n", uid, new->profile.to_uid, new->profile.scontext);
    } else { // add new one
        list_add_rcu(&new->list, &allow_uid_list);
        logkfi("new uid: %d, to_uid: %d, sctx: %s\n", uid, new->profile.to_uid, new->profile.scontext);
    }
    spin_unlock(&list_lock);

    rcu_read_unlock();
    if (old) {
        if (async) {
            call_rcu(&old->rcu, allow_reclaim_callback);
        } else {
            synchronize_rcu();
            kfree(old);
        }
    }
    return 0;
}

int su_remove_allow_uid(uid_t uid, int async)
{
    struct allow_uid *pos;
    spin_lock(&list_lock);
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        if (pos->uid == uid) {
            list_del_rcu(&pos->list);
            spin_unlock(&list_lock);
            logkfi("uid: %d, to_uid: %d, sctx: %s\n", pos->uid, pos->profile.to_uid, pos->profile.scontext);
            if (async) {
                call_rcu(&pos->rcu, allow_reclaim_callback);
            } else {
                synchronize_rcu();
                kfree(pos);
            }
            return 0;
        }
    }
    spin_unlock(&list_lock);
    return 0;
}

int su_allow_uid_nums()
{
    int num = 0;
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        num++;
    }
    rcu_read_unlock();
    logkfd("%d\n", num);
    return num;
}

int su_allow_uids(uid_t *__user uuids, int unum)
{
    int rc = 0;
    int num = 0;
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        if (num >= unum) {
            goto out;
        }
        uid_t uid = pos->profile.uid;
        int cplen = seq_copy_to_user(uuids + num, &uid, sizeof(uid));
        logkfd("uid: %d\n", uid);
        if (cplen <= 0) {
            logkfd("seq_copy_to_user error: %d", cplen);
            rc = cplen;
            goto out;
        }
        num++;
    }
    rc = num;
out:
    rcu_read_unlock();
    return rc;
}

int su_allow_uid_profile(uid_t uid, struct su_profile *__user uprofile)
{
    int rc = -ENOENT;
    rcu_read_lock();
    struct allow_uid *pos;
    list_for_each_entry(pos, &allow_uid_list, list)
    {
        if (pos->profile.uid != uid) continue;
        int cplen = seq_copy_to_user(uprofile, &pos->profile, sizeof(struct su_profile));
        logkfd("profile: %d %d %s\n", uid, pos->profile.to_uid, pos->profile.scontext);
        if (cplen <= 0) {
            logkfd("seq_copy_to_user error: %d", cplen);
            rc = cplen;
            goto out;
        }
        rc = 0;
        goto out;
    }
out:
    rcu_read_unlock();
    return rc;
}

// no free, no lock
int su_reset_path(const char *path)
{
    if (!strcmp(current_su_path, path)) return 0;
    char *new_su_path = kstrdup(path, GFP_ATOMIC);
    current_su_path = new_su_path;
    dsb(ishst);
    logkfi("%s\n", current_su_path);
    return 0;
}

int su_get_path(char *__user ubuf, int buf_len)
{
    int len = strnlen(current_su_path, SU_PATH_MAX_LEN);
    if (buf_len < len) return -ENOMEM;
    logkfi("%s\n", current_su_path);
    return seq_copy_to_user(ubuf, current_su_path, len + 1);
}

// todo: rcu_dereference_protected
static uid_t current_uid()
{
    struct cred *cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
    return uid;
}

static void *__user copy_to_user_stack(void *data, size_t len)
{
    uintptr_t addr = current_user_stack_pointer();
    addr -= len;
    addr &= 0xFFFFFFFFFFFFFFF0;
    seq_copy_to_user((void *)addr, data, len);
    return (void *)addr;
}

static inline char *__user android_sh_user_path()
{
    return (char *__user)copy_to_user_stack((void *)sh_path, sizeof(sh_path));
}

static inline char *__user android_su_user_path()
{
    return (char *__user)copy_to_user_stack((void *)su_path, sizeof(su_path));
}

// int do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
// int __do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags,
//                      struct file *file);
// static int do_execve_common(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp)
static void before_do_execve(hook_fargs8_t *args, void *udata)
{
    struct filename *filename;
    int filename_index = 0;
    if ((((uintptr_t)args->arg0) & 0xFFFF000000000000) != 0xFFFF000000000000) {
        // int, AT_FDCWD(ffffff9c) or fd
        filename_index = 1;
    }
    filename = (struct filename *)args->args[filename_index];

    if (!filename || IS_ERR(filename)) return;

    if (!strcmp(current_su_path, filename->name)) {
        uid_t uid = current_uid();
        struct su_profile *profile = search_allow_uid(uid);
        if (!profile) return;

        uid_t to_uid = profile->to_uid;
        const char *sctx = profile->scontext;
        commit_su(to_uid, sctx);

        struct file *filp = filp_open(apd_path, O_RDONLY, 0);
        if (IS_ERR(filp)) {
            logkfi("call su uid: %d, to_uid: %d, sctx: %s\n", uid, to_uid, sctx);
            strcpy((char *)filename->name, sh_path);
        } else {
            filp_close(filp, 0);
            logkfi("call apd uid: %d, to_uid: %d, sctx: %s\n", uid, to_uid, sctx);
            strcpy((char *)filename->name, apd_path);
            const char *__user p0 =
                get_user_arg_ptr((void *)args->args[filename_index + 1], (void *)args->args[filename_index + 2], 0);
            int sz = seq_copy_to_user((char *__user)p0, sh_path, sizeof(sh_path));
            if (sz != sizeof(sh_path)) logkfe("seq_copy_to_user error: %d\n", sz);
        }
        kvfree(profile);
    } else if (!strcmp(kpatch_shadow_path, filename->name)) {
        const char __user *p1 =
            get_user_arg_ptr((void *)args->args[filename_index + 1], (void *)args->args[filename_index + 2], 1);
        if (!p1 || IS_ERR(p1)) return;
        char arg1[SUPER_KEY_LEN];
        if (strncpy_from_user_nofault(arg1, p1, sizeof(arg1)) <= 0) return;
        if (superkey_auth(arg1, strlen(arg1))) return;
        commit_su(0, 0);
        strcpy((char *)filename->name, kpatch_path);
        // log
        char log_buf[512];
        int log_off = 0;
        for (int i = 2; i < 6; i++) {
            const char *pn =
                get_user_arg_ptr((void *)args->args[filename_index + 1], (void *)args->args[filename_index + 2], i);
            if (!pn || IS_ERR(pn)) break;
            log_off += strncpy_from_user_nofault(log_buf + log_off, pn, sizeof(log_buf) - log_off);
            log_buf[log_off - 1] = ' ';
        }
        log_buf[log_off > 0 ? log_off - 1 : 0] = '\0';
        logkfd("%s ****** %s\n", filename->name, log_buf);
    }

    return;
}

// long do_faccessat(int dfd, const char __user *filename, int mode, int flags)
// SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
static void before_faccessat(hook_fargs4_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (!is_allow_uid(uid)) return;

    const char *local_su_path = current_su_path;

    char __user *filename = (char __user *)args->arg1;
    char buf[SU_PATH_MAX_LEN];
    strncpy_from_user_nofault(buf, filename, sizeof(buf));
    if (strcmp(buf, local_su_path)) return;

    logkfd("uid: %d\n", uid);
    args->ret = 0;
    args->skip_origin = 1;
}

// int vfs_statx(int dfd, struct filename *filename, int flags, struct kstat *stat, u32 request_mask)
// int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
// int do_statx(int dfd, struct filename *filename, unsigned int flags, unsigned int mask, struct statx __user *buffer)
// int do_statx(int dfd, const char __user *filename, unsigned flags, unsigned int mask, struct statx __user *buffer)
// int vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
static void before_stat(hook_fargs8_t *args, void *udata)
{
    int change_flag = 0;
    args->local.data[0] = change_flag;

    uid_t uid = current_uid();
    if (!is_allow_uid(uid)) return;

    struct filename *filename = 0;
    char *__user u_filename = 0;

    const char *local_su_path = current_su_path;

    // assume this is kernel address
    if ((((uintptr_t)args->arg1) & 0xFFFF000000000000) == 0xFFFF000000000000) {
        filename = (struct filename *)args->arg1;
        if (IS_ERR(filename)) return;
        if (strcmp(filename->name, local_su_path)) return;
    } else {
        u_filename = (char *)args->arg1;
        char buf[SU_PATH_MAX_LEN];
        strncpy_from_user_nofault(buf, u_filename, sizeof(buf));
        if (strcmp(buf, local_su_path)) return;
    }

    if (filename) {
        logkfd("0 uid: %d\n", uid);
        strcpy((char *)filename->name, sh_path);
    } else {
        logkfd("1 uid: %d\n", uid);
        int sz = seq_copy_to_user(u_filename, sh_path, sizeof(sh_path));
        if (sz != sizeof(sh_path)) logkfe("seq_copy_to_user error: %d\n", sz);
        change_flag = 1;
        args->local.data[0] = change_flag;
        args->local.data[1] = (uint64_t)local_su_path;
    }
}

static void after_stat(hook_fargs8_t *args, void *udata)
{
    int change_flag = args->local.data[0];
    if (change_flag) {
        const char *local_su_path = (const char *)args->local.data[1];
        int sz = seq_copy_to_user((void *)args->arg1, local_su_path, strlen(local_su_path) + 1);
        if (sz != strlen(local_su_path) + 1) logkfe("seq_copy_to_user error: %d\n", sz);
    }
}

// // static ssize_t path_getxattr(const char __user *pathname, const char __user *name, void __user *value, size_t size, unsigned int lookup_flags)
// static void before_path_getxattr(hook_fargs5_t *args, void *udata)
// {
//     int change_flag = 0;
//     args->local.data[0] = change_flag;

//     char buf[sizeof(su_path)];
//     strncpy_from_user_nofault(buf, (char *__user)args->arg0, sizeof(buf));
//     if (strcmp(su_path, buf)) return;

//     uid_t uid = current_uid();
//     if (!is_allow_uid(uid)) return;

//     logkfd("uid: %d\n", uid);
//     int sz = seq_copy_to_user((char *__user)args->arg0, sh_path, sizeof(sh_path));
//     if (sz != sizeof(sh_path)) logkfe("seq_copy_to_user error: %d\n", sz);

//     change_flag = 1;
//     args->local.data[0] = change_flag;
// }

// static void after_path_getxattr(hook_fargs5_t *args, void *udata)
// {
//     int change_flag = args->local.data[0];
//     if (change_flag) {
//         int sz = seq_copy_to_user((void *)args->arg0, su_path, sizeof(su_path));
//         if (sz != sizeof(su_path)) logkfe("seq_copy_to_user error: %d\n", sz);
//     }
// }

int su_compat_init()
{
    int rc = 0;

    current_su_path = su_path;
    INIT_LIST_HEAD(&allow_uid_list);
    spin_lock_init(&list_lock);

    // default shell
    struct su_profile default_shell_profile = {
        .uid = 2000,
        .to_uid = 0,
    };
    su_add_allow_uid(default_shell_profile.uid, &default_shell_profile, 1);

    // state
    unsigned long vfs_stat_addr = kallsyms_lookup_name("vfs_statx");
    if (!vfs_stat_addr) vfs_stat_addr = kallsyms_lookup_name("do_statx");
    if (!vfs_stat_addr) vfs_stat_addr = kallsyms_lookup_name("vfs_fstatat");
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
    if (!faccessat_addr) faccessat_addr = kallsyms_lookup_name("sys_faccessat");
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

    // xattr
    // unsigned long path_getxattr_addr = kallsyms_lookup_name("path_getxattr");
    // if (!path_getxattr_addr) {
    //     log_boot("no symbol do_faccessat or sys_faccessat\n");
    //     rc = -ENOENT;
    //     goto out;
    // } else {
    // hook_err_t err = hook_wrap5((void *)path_getxattr_addr, before_path_getxattr, after_path_getxattr, 0);
    // if (err) {
    //     log_boot("hook do_faccessat error: %d\n", err);
    //     rc = err;
    //     goto out;
    // }
    // }

out:
    return rc;
}