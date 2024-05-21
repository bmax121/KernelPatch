#ifndef _LINUX_CRED_H
#define _LINUX_CRED_H

#include <ktypes.h>
#include <ksyms.h>

struct cred; // __randomize_layout
struct inode;
struct task_struct; // __randomize_layout
struct group_info; // __randomize_layout

#define CRED_MAGIC 0x43736564
#define CRED_MAGIC_DEAD 0x44656144

extern struct group_info *kfunc_def(groups_alloc)(int gidsetsize);
extern void groups_free(struct group_info *);

extern int in_group_p(kgid_t);
extern int in_egroup_p(kgid_t);
extern int groups_search(const struct group_info *, kgid_t);

extern int set_current_groups(struct group_info *);
extern void kfunc_def(set_groups)(struct cred *, struct group_info *group_info);
extern bool may_setgroups(void);
extern void groups_sort(struct group_info *);

static inline void set_groups(struct cred *new, struct group_info *group_info)
{
    kfunc_call_void(set_groups, new, group_info);
}

static inline struct group_info *groups_alloc(int gidsetsize)
{
    kfunc_call(groups_alloc, gidsetsize);
    return 0;
}

struct cred_offset
{
    int16_t usage_offset;
    int16_t subscribers_offset;
    int16_t magic_offset;

    int16_t uid_offset;
    int16_t gid_offset;
    int16_t suid_offset;
    int16_t sgid_offset;
    int16_t euid_offset;
    int16_t egid_offset;
    int16_t fsuid_offset;
    int16_t fsgid_offset;
    int16_t securebits_offset;
    int16_t cap_inheritable_offset;
    int16_t cap_permitted_offset;
    int16_t cap_effective_offset;
    int16_t cap_bset_offset;
    int16_t cap_ambient_offset;

    int16_t user_offset;
    int16_t user_ns_offset;
    int16_t ucounts_offset;
    int16_t group_info_offset;

    int16_t session_keyring_offset;
    int16_t process_keyring_offset;
    int16_t thread_keyring_offset;
    int16_t request_key_auth_offset;

    int16_t security_offset;

    int16_t rcu_offset;
};

extern struct cred_offset cred_offset;

void try_cred_offset();

extern void kfunc_def(__put_cred)(struct cred *cred);
extern void kfunc_def(exit_creds)(struct task_struct *task);
extern int kfunc_def(copy_creds)(struct task_struct *p, unsigned long clone_flags);
extern const struct cred *kfunc_def(get_task_cred)(struct task_struct *task);
extern struct cred *kfunc_def(cred_alloc_blank)(void);
extern struct cred *kfunc_def(prepare_creds)(void);
extern struct cred *kfunc_def(prepare_exec_creds)(void);
extern int kfunc_def(commit_creds)(struct cred *new);
extern void kfunc_def(abort_creds)(struct cred *new);
extern const struct cred *kfunc_def(override_creds)(const struct cred *new);
extern void kfunc_def(revert_creds)(const struct cred *old);
extern struct cred *kfunc_def(prepare_kernel_cred)(struct task_struct *daemon);
extern int kfunc_def(change_create_files_as)(struct cred *cred, struct inode *inode);
extern int kfunc_def(set_security_override)(struct cred *a, u32 secid);
extern int kfunc_def(set_security_override_from_ctx)(struct cred *new, const char *secctx);
extern int kfunc_def(set_create_files_as)(struct cred *new, struct inode *inode);
extern int kfunc_def(cred_fscmp)(const struct cred *a, const struct cred *b);
extern void kfunc_def(cred_init)(void);
extern bool kfunc_def(creds_are_invalid)(const struct cred *cred);

static inline void __put_cred(struct cred *cred)
{
    kfunc_direct_call(__put_cred, cred);
}

static inline void exit_creds(struct task_struct *task)
{
    kfunc_direct_call_void(exit_creds, task);
}

static inline int copy_creds(struct task_struct *p, unsigned long clone_flags)
{
    kfunc_direct_call(copy_creds, p, clone_flags);
}

static inline const struct cred *get_task_cred(struct task_struct *task)
{
    kfunc_direct_call(get_task_cred, task);
}

static inline struct cred *cred_alloc_blank(void)
{
    kfunc_direct_call(cred_alloc_blank);
}

static inline struct cred *prepare_creds(void)
{
    kfunc_direct_call(prepare_creds);
}

static inline struct cred *prepare_exec_creds(void)
{
    kfunc_direct_call(prepare_exec_creds);
}

static inline int commit_creds(struct cred *new)
{
    kfunc_direct_call(commit_creds, new);
}

static inline void abort_creds(struct cred *new)
{
    kfunc_direct_call_void(abort_creds, new);
}

static inline const struct cred *override_creds(const struct cred *new)
{
    kfunc_direct_call(override_creds, new);
}

static inline void revert_creds(const struct cred *old)
{
    kfunc_direct_call(revert_creds, old);
}

static inline struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
    kfunc_direct_call(prepare_kernel_cred, daemon);
}

static inline int set_security_override(struct cred *new, u32 secid)
{
    kfunc_direct_call(set_security_override, new, secid);
}

static inline int set_security_override_from_ctx(struct cred *new, const char *secctx)
{
    kfunc_direct_call(set_security_override_from_ctx, new, secctx);
}

static inline int cred_fscmp(const struct cred *a, const struct cred *b)
{
    kfunc_direct_call(cred_fscmp, a, b);
}

static inline bool creds_are_invalid(const struct cred *cred)
{
    kfunc_direct_call(creds_are_invalid, cred);
}

#endif
