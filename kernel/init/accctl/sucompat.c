#include <linux/list.h>
#include <ktypes.h>
#include <stdbool.h>
#include <linux/vmalloc.h>
#include <syscall.h>
#include <ksyms.h>
#include <hook.h>
#include <minc/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define SU_UID_IGNORE 0
#define SU_UID_ALLOW 1
#define SU_UID_DENY 2

static const char *su_path = 0;
static const char *sh_path = 0;

struct su_uid_list
{
    uid_t uid;
    int rule;
    struct list_head list;
};

static struct su_uid_list su_allow_list;

int su_get_uid_rule(uid_t uid)
{
    struct su_uid_list *pos;
    list_for_each_entry(pos, &su_allow_list.list, list)
    {
        if (uid == pos->uid)
            return pos->rule;
    }
    return SU_UID_IGNORE;
}

static inline bool is_su_allow(uid_t uid)
{
    return su_get_uid_rule(uid) == SU_UID_ALLOW;
}

static inline bool is_su_deny(uid_t uid)
{
    return su_get_uid_rule(uid) == SU_UID_DENY;
}

// todo: rcu list, delete ignore rule
int su_modify_uid_rule(uid_t uid, bool rule)
{
    struct su_uid_list *pos;
    list_for_each_entry(pos, &su_allow_list.list, list)
    {
        if (uid == pos->uid) {
            pos->rule = rule;
        }
        return 0;
    }
    struct su_uid_list *elem = (struct su_uid_list *)vmalloc(sizeof(struct su_uid_list));
    elem->rule = SU_UID_IGNORE;
    elem->uid = uid;
    elem->rule = rule;
    list_add_tail(&elem->list, &su_allow_list.list);
    return 0;
}

static inline void su_allow_uid(uid_t uid)
{
    su_modify_uid_rule(uid, SU_UID_ALLOW);
}

static inline void su_deny_uid(uid_t uid)
{
    su_modify_uid_rule(uid, SU_UID_DENY);
}

static inline void su_ignore_uid(uid_t uid)
{
    su_modify_uid_rule(uid, SU_UID_IGNORE);
}

struct user_arg_ptr
{
    union
    {
        const char __user *const __user *native;
    } ptr;
};

typedef u32 compat_uptr_t;
struct user_arg_ptr_compat
{
    bool is_compat;
    union
    {
        const compat_uptr_t __user *compat;
    } ptr;
};

struct file;

// int do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
// int __do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags,
//                      struct file *file);

static int (*backup_do_execve)(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp,
                               int flags, struct file *file, long _p) = 0;

static int replace_do_execve(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp,
                             int flags, struct file *file, long _p)
{
    logkfd("filename: %s %s\n", filename->name, filename->iname);

    int rc = backup_do_execve(fd, filename, argv, envp, flags, file, _p);

    return rc;
}

static long (*backup_do_faccessat)(int dfd, const char __user *filename, int mode) = 0;

static long replace_do_faccessat(int dfd, const char __user *filename, int mode)
{
    char buf[64] = { '\0' };
    strncpy_from_user(buf, filename, 63);
    logkfd("filename: %s\n", buf);

    int rc = backup_do_faccessat(dfd, filename, mode);
    return rc;
}

int su_compat_init()
{
    INIT_LIST_HEAD(&su_allow_list.list);

    sh_path = "/system/bin/sh";
    su_path = "/system/bin/su";

    unsigned long hook_execve_addr = kallsyms_lookup_name("__do_execve_file");
    if (!hook_execve_addr)
        hook_execve_addr = kallsyms_lookup_name("do_execveat_common");
    if (!hook_execve_addr) {
        logkfe("su compat execve not found\n");
    }

    hook_err_t err = hook((void *)hook_execve_addr, (void *)replace_do_execve, (void **)&backup_do_execve);
    if (err != HOOK_NO_ERR) {
        logkfe("su compat hook error\n");
    }

    return 0;
}