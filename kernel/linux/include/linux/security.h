#ifndef __LINUX_SECURITY_H
#define __LINUX_SECURITY_H

#include <ktypes.h>
#include <linux/capability.h>
#include <ksyms.h>

typedef struct
{
    union
    {
        void *kernel;
        void __user *user;
    };
    bool is_kernel : 1;
} sockptr_t;

struct linux_binprm;
struct cred;
struct rlimit;
struct kernel_siginfo;
struct sembuf;
struct kern_ipc_perm;
struct audit_context;
struct super_block;
struct inode;
struct dentry;
struct file;
struct vfsmount;
struct path;
struct qstr;
struct iattr;
struct fown_struct;
struct file_operations;
struct msg_msg;
struct xattr;
struct kernfs_node;
struct xfrm_sec_ctx;
struct mm_struct;
struct fs_context;
struct fs_parameter;
enum fs_value_type;
struct watch;
struct watch_notification;
struct ctl_table;
struct audit_krule;
struct user_namespace;
struct timezone;
struct msghdr;
struct sk_buff;
struct sock;
struct sockaddr;
struct socket;
struct flowi_common;
struct dst_entry;
struct xfrm_selector;
struct xfrm_policy;
struct xfrm_state;
struct xfrm_user_sec_ctx;
struct seq_file;
struct sctp_endpoint;
struct timespec64;
struct task_struct;
struct vm_area_struct;
enum kernel_read_file_id;
enum lockdown_reason;
struct key;
struct posix_acl;
struct mnt_idmap;
struct request_sock;
struct sctp_association;
union bpf_attr;
struct bpf_map;
struct bpf_prog_aux;
struct perf_event_attr;
struct perf_event;
struct io_uring_cmd;
struct mnt_idmap;
struct request_sock;
struct sctp_association;
struct bpf_prog;

enum key_need_perm
{
    KEY_NEED_UNSPECIFIED, /* Needed permission unspecified */
    KEY_NEED_ASSUME_AUTHORITY, /* Want to assume instantiation authority */
    KEY_NEED_CHOWN, /* Want to change key's ownership/group */
    KEY_NEED_DESCRIBE, /* Want to get a key's attributes */
    KEY_NEED_GET_SECURITY, /* Want to get a key's security label */
    KEY_NEED_INSTANTIATE, /* Want to instantiate a key */
    KEY_NEED_INVALIDATE, /* Want to invalidate key */
    KEY_NEED_JOIN, /* Want to set a keyring as the session keyring */
    KEY_NEED_KEYRING_ADD, /* Want to add a link to a keyring */
    KEY_NEED_KEYRING_CLEAR, /* Want to clear a keyring */
    KEY_NEED_KEYRING_DELETE, /* Want to remove a link from a keyring */
    KEY_NEED_LINK, /* Want to create a link to a key */
    KEY_NEED_READ, /* Want to read content to userspace */
    KEY_NEED_REVOKE, /* Want to revoke a key */
    KEY_NEED_SEARCH, /* Want to find a key in a search */
    KEY_NEED_SETPERM, /* Want to set the permissions mask */
    KEY_NEED_SET_RESTRICTION, /* Want to set a restriction on a keyring */
    KEY_NEED_SET_TIMEOUT, /* Want to set the expiration time on a key */
    KEY_NEED_UNLINK, /* Want to remove a link from a key */
    KEY_NEED_UPDATE, /* Want to update a key's payload */
    KEY_NEED_USE, /* Want to use a key (in kernel) */
    KEY_NEED_WATCH, /* Want to watch a key for events */
};
enum lsm_event
{
    LSM_POLICY_CHANGE,
};

#define __kernel_read_file_id(id)                                                                                     \
    id(UNKNOWN, unknown) id(FIRMWARE, firmware) id(MODULE, kernel - module) id(KEXEC_IMAGE, kexec - image)            \
        id(KEXEC_INITRAMFS, kexec - initramfs) id(POLICY, security - policy) id(X509_CERTIFICATE, x509 - certificate) \
            id(MAX_ID, )

#define __fid_enumify(ENUM, dummy) READING_##ENUM,
#define __fid_stringify(dummy, str) #str,

enum kernel_read_file_id
{
    __kernel_read_file_id(__fid_enumify)
};

/* Keep the kernel_load_data_id enum in sync with kernel_read_file_id */
#define __data_id_enumify(ENUM, dummy) LOADING_##ENUM,
#define __data_id_stringify(dummy, str) #str,

enum kernel_load_data_id
{
    __kernel_read_file_id(__data_id_enumify)
};

enum lockdown_reason
{
    LOCKDOWN_NONE,
    LOCKDOWN_MODULE_SIGNATURE,
    LOCKDOWN_DEV_MEM,
    LOCKDOWN_EFI_TEST,
    LOCKDOWN_KEXEC,
    LOCKDOWN_HIBERNATION,
    LOCKDOWN_PCI_ACCESS,
    LOCKDOWN_IOPORT,
    LOCKDOWN_MSR,
    LOCKDOWN_ACPI_TABLES,
    LOCKDOWN_PCMCIA_CIS,
    LOCKDOWN_TIOCSSERIAL,
    LOCKDOWN_MODULE_PARAMETERS,
    LOCKDOWN_MMIOTRACE,
    LOCKDOWN_DEBUGFS,
    LOCKDOWN_XMON_WR,
    LOCKDOWN_BPF_WRITE_USER,
    LOCKDOWN_DBG_WRITE_KERNEL,
    LOCKDOWN_INTEGRITY_MAX,
    LOCKDOWN_KCORE,
    LOCKDOWN_KPROBES,
    LOCKDOWN_BPF_READ,
    LOCKDOWN_DBG_READ_KERNEL,
    LOCKDOWN_PERF,
    LOCKDOWN_TRACEFS,
    LOCKDOWN_XMON_RW,
    LOCKDOWN_CONFIDENTIALITY_MAX,
};

typedef int (*initxattrs)(struct inode *inode, const struct xattr *xattr_array, void *fs_data);

/* These functions are in security/commoncap.c */
extern int kfunc_def(cap_capable)(const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts);
extern int kfunc_def(cap_settime)(const struct timespec64 *ts, const struct timezone *tz);
extern int kfunc_def(cap_ptrace_access_check)(struct task_struct *child, unsigned int mode);
extern int kfunc_def(cap_ptrace_traceme)(struct task_struct *parent);
extern int kfunc_def(cap_capget)(struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable,
                                 kernel_cap_t *permitted);
extern int kfunc_def(cap_capset)(struct cred *new, const struct cred *old, const kernel_cap_t *effective,
                                 const kernel_cap_t *inheritable, const kernel_cap_t *permitted);
extern int kfunc_def(cap_bprm_creds_from_file)(struct linux_binprm *bprm, struct file *file);
extern int kfunc_def(cap_inode_setxattr)(struct dentry *dentry, const char *name, const void *value, size_t size,
                                         int flags);
extern int kfunc_def(cap_inode_removexattr)(struct dentry *dentry, const char *name);
extern int kfunc_def(cap_inode_need_killpriv)(struct dentry *dentry);
extern int kfunc_def(cap_inode_killpriv)(struct dentry *dentry);
extern int kfunc_def(cap_inode_getsecurity)(struct inode *inode, const char *name, void **buffer, bool alloc);
extern int kfunc_def(cap_mmap_addr)(unsigned long addr);
extern int kfunc_def(cap_mmap_file)(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags);
extern int kfunc_def(cap_task_fix_setuid)(struct cred *new, const struct cred *old, int flags);
extern int kfunc_def(cap_task_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
                                     unsigned long arg5);
extern int kfunc_def(cap_task_setscheduler)(struct task_struct *p);
extern int kfunc_def(cap_task_setioprio)(struct task_struct *p, int ioprio);
extern int kfunc_def(cap_task_setnice)(struct task_struct *p, int nice);
extern int kfunc_def(cap_vm_enough_memory)(struct mm_struct *mm, long pages);

//
/* Security operations */
extern int kfunc_def(security_binder_set_context_mgr)(const struct cred *mgr);
extern int kfunc_def(security_binder_transaction)(const struct cred *from, const struct cred *to);
extern int kfunc_def(security_binder_transfer_binder)(const struct cred *from, const struct cred *to);
extern int kfunc_def(security_binder_transfer_file)(const struct cred *from, const struct cred *to, struct file *file);
extern int kfunc_def(security_ptrace_access_check)(struct task_struct *child, unsigned int mode);
extern int kfunc_def(security_ptrace_traceme)(struct task_struct *parent);
extern int kfunc_def(security_capget)(struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable,
                                      kernel_cap_t *permitted);
extern int kfunc_def(security_capset)(struct cred *new, const struct cred *old, const kernel_cap_t *effective,
                                      const kernel_cap_t *inheritable, const kernel_cap_t *permitted);
extern int kfunc_def(security_capable)(const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts);
extern int kfunc_def(security_quotactl)(int cmds, int type, int id, struct super_block *sb);
extern int kfunc_def(security_quota_on)(struct dentry *dentry);
extern int kfunc_def(security_syslog)(int type);
extern int kfunc_def(security_settime64)(const struct timespec64 *ts, const struct timezone *tz);
extern int kfunc_def(security_vm_enough_memory_mm)(struct mm_struct *mm, long pages);
extern int kfunc_def(security_bprm_creds_for_exec)(struct linux_binprm *bprm);
extern int kfunc_def(security_bprm_creds_from_file)(struct linux_binprm *bprm, struct file *file);
extern int kfunc_def(security_bprm_check)(struct linux_binprm *bprm);
extern void kfunc_def(security_bprm_committing_creds)(struct linux_binprm *bprm);
extern void kfunc_def(security_bprm_committed_creds)(struct linux_binprm *bprm);
extern int kfunc_def(security_fs_context_dup)(struct fs_context *fc, struct fs_context *src_fc);
extern int kfunc_def(security_fs_context_parse_param)(struct fs_context *fc, struct fs_parameter *param);
extern int kfunc_def(security_sb_alloc)(struct super_block *sb);
extern void kfunc_def(security_sb_delete)(struct super_block *sb);
extern void kfunc_def(security_sb_free)(struct super_block *sb);
extern void kfunc_def(security_free_mnt_opts)(void **mnt_opts);
extern int kfunc_def(security_sb_eat_lsm_opts)(char *options, void **mnt_opts);
extern int kfunc_def(security_sb_remount)(struct super_block *sb, void *mnt_opts);
extern int kfunc_def(security_sb_kern_mount)(struct super_block *sb);
extern int kfunc_def(security_sb_show_options)(struct seq_file *m, struct super_block *sb);
extern int kfunc_def(security_sb_statfs)(struct dentry *dentry);
extern int kfunc_def(security_sb_mount)(const char *dev_name, const struct path *path, const char *type,
                                        unsigned long flags, void *data);
extern int kfunc_def(security_sb_umount)(struct vfsmount *mnt, int flags);
extern int kfunc_def(security_sb_pivotroot)(const struct path *old_path, const struct path *new_path);
extern int kfunc_def(security_sb_set_mnt_opts)(struct super_block *sb, void *mnt_opts, unsigned long kern_flags,
                                               unsigned long *set_kern_flags);
extern int kfunc_def(security_sb_clone_mnt_opts)(const struct super_block *oldsb, struct super_block *newsb,
                                                 unsigned long kern_flags, unsigned long *set_kern_flags);
extern int kfunc_def(security_add_mnt_opt)(const char *option, const char *val, int len, void **mnt_opts);
extern int kfunc_def(security_move_mount)(const struct path *from_path, const struct path *to_path);
extern int kfunc_def(security_dentry_init_security)(struct dentry *dentry, int mode, const struct qstr *name,
                                                    void **ctx, u32 *ctxlen);
extern int kfunc_def(security_dentry_create_files_as)(struct dentry *dentry, int mode, struct qstr *name,
                                                      const struct cred *old, struct cred *new);

//CONFIG_SECURITY_PATH
extern int kfunc_def(security_path_unlink)(const struct path *dir, struct dentry *dentry);
extern int kfunc_def(security_path_mkdir)(const struct path *dir, struct dentry *dentry, umode_t mode);
extern int kfunc_def(security_path_rmdir)(const struct path *dir, struct dentry *dentry);
extern int kfunc_def(security_path_mknod)(const struct path *dir, struct dentry *dentry, umode_t mode,
                                          unsigned int dev);
extern int kfunc_def(security_path_truncate)(const struct path *path);
extern int kfunc_def(security_path_symlink)(const struct path *dir, struct dentry *dentry, const char *old_name);
extern int kfunc_def(security_path_link)(struct dentry *old_dentry, const struct path *new_dir,
                                         struct dentry *new_dentry);
extern int kfunc_def(security_path_rename)(const struct path *old_dir, struct dentry *old_dentry,
                                           const struct path *new_dir, struct dentry *new_dentry, unsigned int flags);
extern int kfunc_def(security_path_chmod)(const struct path *path, umode_t mode);
extern int kfunc_def(security_path_chown)(const struct path *path, kuid_t uid, kgid_t gid);
extern int kfunc_def(security_path_chroot)(const struct path *path);
/* CONFIG_SECURITY_PATH */

/* Needed for inode based security check */
extern int kfunc_def(security_path_notify)(const struct path *path, u64 mask, unsigned int obj_type);
extern int kfunc_def(security_inode_alloc)(struct inode *inode);
extern void kfunc_def(security_inode_free)(struct inode *inode);
extern int kfunc_def(security_inode_init_security)(struct inode *inode, struct inode *dir, const struct qstr *qstr,
                                                   initxattrs initxattrs, void *fs_data);
extern int kfunc_def(security_old_inode_init_security)(struct inode *inode, struct inode *dir, const struct qstr *qstr,
                                                       const char **name, void **value, size_t *len);
extern int kfunc_def(security_inode_create)(struct inode *dir, struct dentry *dentry, umode_t mode);
extern int kfunc_def(security_inode_link)(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);
extern int kfunc_def(security_inode_unlink)(struct inode *dir, struct dentry *dentry);
extern int kfunc_def(security_inode_symlink)(struct inode *dir, struct dentry *dentry, const char *old_name);
extern int kfunc_def(security_inode_mkdir)(struct inode *dir, struct dentry *dentry, umode_t mode);
extern int kfunc_def(security_inode_rmdir)(struct inode *dir, struct dentry *dentry);
extern int kfunc_def(security_inode_mknod)(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev);
extern int kfunc_def(security_inode_rename)(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
                                            struct dentry *new_dentry, unsigned int flags);
extern int kfunc_def(security_inode_readlink)(struct dentry *dentry);
extern int kfunc_def(security_inode_follow_link)(struct dentry *dentry, struct inode *inode, bool rcu);
extern int kfunc_def(security_inode_permission)(struct inode *inode, int mask);
extern int kfunc_def(security_inode_setattr)(struct dentry *dentry, struct iattr *attr);
extern int kfunc_def(security_inode_getattr)(const struct path *path);
extern int kfunc_def(security_inode_setxattr)(struct dentry *dentry, const char *name, const void *value, size_t size,
                                              int flags);
extern void kfunc_def(security_inode_post_setxattr)(struct dentry *dentry, const char *name, const void *value,
                                                    size_t size, int flags);
extern int kfunc_def(security_inode_getxattr)(struct dentry *dentry, const char *name);
extern int kfunc_def(security_inode_listxattr)(struct dentry *dentry);
extern int kfunc_def(security_inode_removexattr)(struct dentry *dentry, const char *name);
extern int kfunc_def(security_inode_set_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name,
                                             struct posix_acl *kacl);
extern int kfunc_def(security_inode_get_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name);
extern int kfunc_def(security_inode_remove_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name);
extern int kfunc_def(security_inode_need_killpriv)(struct dentry *dentry);
extern int kfunc_def(security_inode_killpriv)(struct dentry *dentry);
extern int kfunc_def(security_inode_getsecurity)(struct inode *inode, const char *name, void **buffer, bool alloc);
extern int kfunc_def(security_inode_setsecurity)(struct inode *inode, const char *name, const void *value, size_t size,
                                                 int flags);
extern int kfunc_def(security_inode_listsecurity)(struct inode *inode, char *buffer, size_t buffer_size);
extern void kfunc_def(security_inode_getsecid)(struct inode *inode, u32 *secid);
extern int kfunc_def(security_inode_copy_up)(struct dentry *src, struct cred **new);
extern int kfunc_def(security_inode_copy_up_xattr)(const char *name);
extern int kfunc_def(security_kernfs_init_security)(struct kernfs_node *kn_dir, struct kernfs_node *kn);
extern int kfunc_def(security_file_permission)(struct file *file, int mask);
extern int kfunc_def(security_file_alloc)(struct file *file);
extern void kfunc_def(security_file_free)(struct file *file);
extern int kfunc_def(security_file_ioctl)(struct file *file, unsigned int cmd, unsigned long arg);
extern int kfunc_def(security_mmap_addr)(unsigned long addr);
extern int kfunc_def(security_mmap_file)(struct file *file, unsigned long prot, unsigned long flags);
extern int kfunc_def(security_file_mprotect)(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot);
extern int kfunc_def(security_file_lock)(struct file *file, unsigned int cmd);
extern int kfunc_def(security_file_fcntl)(struct file *file, unsigned int cmd, unsigned long arg);
extern void kfunc_def(security_file_set_fowner)(struct file *file);
extern int kfunc_def(security_file_send_sigiotask)(struct task_struct *tsk, struct fown_struct *fown, int sig);
extern int kfunc_def(security_file_receive)(struct file *file);
// extern int kfunc_def(security_file_open)(struct file *file);
extern int kfunc_def(security_file_open)(struct file *file, const struct cred *cred);
extern int kfunc_def(security_file_truncate)(struct file *file);
extern int kfunc_def(security_task_alloc)(struct task_struct *task, unsigned long clone_flags);
extern void kfunc_def(security_task_free)(struct task_struct *task);
extern int kfunc_def(security_cred_alloc_blank)(struct cred *cred, gfp_t gfp);
extern void kfunc_def(security_cred_free)(struct cred *cred);
extern int kfunc_def(security_prepare_creds)(struct cred *new, const struct cred *old, gfp_t gfp);
extern void kfunc_def(security_transfer_creds)(struct cred *new, const struct cred *old);
extern void kfunc_def(security_cred_getsecid)(const struct cred *c, u32 *secid);
extern int kfunc_def(security_kernel_act_as)(struct cred *new, u32 secid);
extern int kfunc_def(security_kernel_create_files_as)(struct cred *new, struct inode *inode);
extern int kfunc_def(security_kernel_module_request)(char *kmod_name);
extern int kfunc_def(security_kernel_load_data)(enum kernel_load_data_id id, bool contents);
extern int kfunc_def(security_kernel_post_load_data)(char *buf, loff_t size, enum kernel_load_data_id id,
                                                     char *description);
extern int kfunc_def(security_kernel_read_file)(struct file *file, enum kernel_read_file_id id, bool contents);
extern int kfunc_def(security_kernel_post_read_file)(struct file *file, char *buf, loff_t size,
                                                     enum kernel_read_file_id id);
extern int kfunc_def(security_task_fix_setuid)(struct cred *new, const struct cred *old, int flags);
extern int kfunc_def(security_task_fix_setgid)(struct cred *new, const struct cred *old, int flags);
extern int kfunc_def(security_task_fix_setgroups)(struct cred *new, const struct cred *old);
extern int kfunc_def(security_task_setpgid)(struct task_struct *p, pid_t pgid);
extern int kfunc_def(security_task_getpgid)(struct task_struct *p);
extern int kfunc_def(security_task_getsid)(struct task_struct *p);
extern void kfunc_def(security_current_getsecid_subj)(u32 *secid);
extern void kfunc_def(security_task_getsecid_obj)(struct task_struct *p, u32 *secid); // ?-6.3
extern void kfunc_def(security_task_getsecid)(struct task_struct *p, u32 *secid); // 4.4-?
extern int kfunc_def(security_task_setnice)(struct task_struct *p, int nice);
extern int kfunc_def(security_task_setioprio)(struct task_struct *p, int ioprio);
extern int kfunc_def(security_task_getioprio)(struct task_struct *p);
extern int kfunc_def(security_task_prlimit)(const struct cred *cred, const struct cred *tcred, unsigned int flags);
extern int kfunc_def(security_task_setrlimit)(struct task_struct *p, unsigned int resource, struct rlimit *new_rlim);
extern int kfunc_def(security_task_setscheduler)(struct task_struct *p);
extern int kfunc_def(security_task_getscheduler)(struct task_struct *p);
extern int kfunc_def(security_task_movememory)(struct task_struct *p);
extern int kfunc_def(security_task_kill)(struct task_struct *p, struct kernel_siginfo *info, int sig,
                                         const struct cred *cred);
extern int kfunc_def(security_task_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
                                          unsigned long arg5);
extern void kfunc_def(security_task_to_inode)(struct task_struct *p, struct inode *inode);
extern int kfunc_def(security_create_user_ns)(const struct cred *cred);
extern int kfunc_def(security_ipc_permission)(struct kern_ipc_perm *ipcp, short flag);
extern void kfunc_def(security_ipc_getsecid)(struct kern_ipc_perm *ipcp, u32 *secid);
extern int kfunc_def(security_msg_msg_alloc)(struct msg_msg *msg);
extern void kfunc_def(security_msg_msg_free)(struct msg_msg *msg);
extern int kfunc_def(security_msg_queue_alloc)(struct kern_ipc_perm *msq);
extern void kfunc_def(security_msg_queue_free)(struct kern_ipc_perm *msq);
extern int kfunc_def(security_msg_queue_associate)(struct kern_ipc_perm *msq, int msqflg);
extern int kfunc_def(security_msg_queue_msgctl)(struct kern_ipc_perm *msq, int cmd);
extern int kfunc_def(security_msg_queue_msgsnd)(struct kern_ipc_perm *msq, struct msg_msg *msg, int msqflg);
extern int kfunc_def(security_msg_queue_msgrcv)(struct kern_ipc_perm *msq, struct msg_msg *msg,
                                                struct task_struct *target, long type, int mode);
extern int kfunc_def(security_shm_alloc)(struct kern_ipc_perm *shp);
extern void kfunc_def(security_shm_free)(struct kern_ipc_perm *shp);
extern int kfunc_def(security_shm_associate)(struct kern_ipc_perm *shp, int shmflg);
extern int kfunc_def(security_shm_shmctl)(struct kern_ipc_perm *shp, int cmd);
extern int kfunc_def(security_shm_shmat)(struct kern_ipc_perm *shp, char __user *shmaddr, int shmflg);
extern int kfunc_def(security_sem_alloc)(struct kern_ipc_perm *sma);
extern void kfunc_def(security_sem_free)(struct kern_ipc_perm *sma);
extern int kfunc_def(security_sem_associate)(struct kern_ipc_perm *sma, int semflg);
extern int kfunc_def(security_sem_semctl)(struct kern_ipc_perm *sma, int cmd);
extern int kfunc_def(security_sem_semop)(struct kern_ipc_perm *sma, struct sembuf *sops, unsigned nsops, int alter);
extern void kfunc_def(security_d_instantiate)(struct dentry *dentry, struct inode *inode);
extern int kfunc_def(security_getprocattr)(struct task_struct *p, const char *lsm, char *name, char **value);
extern int kfunc_def(security_setprocattr)(const char *lsm, const char *name, void *value, size_t size);
extern int kfunc_def(security_netlink_send)(struct sock *sk, struct sk_buff *skb);
extern int kfunc_def(security_ismaclabel)(const char *name);
extern int kfunc_def(security_secid_to_secctx)(u32 secid, char **secdata, u32 *seclen);
extern int kfunc_def(security_secctx_to_secid)(const char *secdata, u32 seclen, u32 *secid);
extern void kfunc_def(security_release_secctx)(char *secdata, u32 seclen);
extern void kfunc_def(security_inode_invalidate_secctx)(struct inode *inode);
extern int kfunc_def(security_inode_notifysecctx)(struct inode *inode, void *ctx, u32 ctxlen);
extern int kfunc_def(security_inode_setsecctx)(struct dentry *dentry, void *ctx, u32 ctxlen);
extern int kfunc_def(security_inode_getsecctx)(struct inode *inode, void **ctx, u32 *ctxlen);

// CONFIG_WATCH_QUEUE
extern int kfunc_def(security_post_notification)(const struct cred *w_cred, const struct cred *cred,
                                                 struct watch_notification *n);

// CONFIG_KEY_NOTIFICATIONS
extern int kfunc_def(security_watch_key)(struct key *key);

// CONFIG_SECURITY_NETWORK
extern int kfunc_def(security_unix_stream_connect)(struct sock *sock, struct sock *other, struct sock *newsk);
extern int kfunc_def(security_unix_may_send)(struct socket *sock, struct socket *other);
extern int kfunc_def(security_socket_create)(int family, int type, int protocol, int kern);
extern int kfunc_def(security_socket_post_create)(struct socket *sock, int family, int type, int protocol, int kern);
extern int kfunc_def(security_socket_socketpair)(struct socket *socka, struct socket *sockb);
extern int kfunc_def(security_socket_bind)(struct socket *sock, struct sockaddr *address, int addrlen);
extern int kfunc_def(security_socket_connect)(struct socket *sock, struct sockaddr *address, int addrlen);
extern int kfunc_def(security_socket_listen)(struct socket *sock, int backlog);
extern int kfunc_def(security_socket_accept)(struct socket *sock, struct socket *newsock);
extern int kfunc_def(security_socket_sendmsg)(struct socket *sock, struct msghdr *msg, int size);
extern int kfunc_def(security_socket_recvmsg)(struct socket *sock, struct msghdr *msg, int size, int flags);
extern int kfunc_def(security_socket_getsockname)(struct socket *sock);
extern int kfunc_def(security_socket_getpeername)(struct socket *sock);
extern int kfunc_def(security_socket_getsockopt)(struct socket *sock, int level, int optname);
extern int kfunc_def(security_socket_setsockopt)(struct socket *sock, int level, int optname);
extern int kfunc_def(security_socket_shutdown)(struct socket *sock, int how);
extern int kfunc_def(security_sock_rcv_skb)(struct sock *sk, struct sk_buff *skb);
extern int kfunc_def(security_socket_getpeersec_stream)(struct socket *sock, sockptr_t optval, sockptr_t optlen,
                                                        unsigned int len);
extern int kfunc_def(security_socket_getpeersec_dgram)(struct socket *sock, struct sk_buff *skb, u32 *secid);
extern int kfunc_def(security_sk_alloc)(struct sock *sk, int family, gfp_t priority);
extern void kfunc_def(security_sk_free)(struct sock *sk);
extern void kfunc_def(security_sk_clone)(const struct sock *sk, struct sock *newsk);
extern void kfunc_def(security_sk_classify_flow)(struct sock *sk, struct flowi_common *flic);
extern void kfunc_def(security_req_classify_flow)(const struct request_sock *req, struct flowi_common *flic);
extern void kfunc_def(security_sock_graft)(struct sock *sk, struct socket *parent);
extern int kfunc_def(security_inet_conn_request)(const struct sock *sk, struct sk_buff *skb, struct request_sock *req);
extern void kfunc_def(security_inet_csk_clone)(struct sock *newsk, const struct request_sock *req);
extern void kfunc_def(security_inet_conn_established)(struct sock *sk, struct sk_buff *skb);
extern int kfunc_def(security_secmark_relabel_packet)(u32 secid);
extern void kfunc_def(security_secmark_refcount_inc)(void);
extern void kfunc_def(security_secmark_refcount_dec)(void);
extern int kfunc_def(security_tun_dev_alloc_security)(void **security);
extern void kfunc_def(security_tun_dev_free_security)(void *security);
extern int kfunc_def(security_tun_dev_create)(void);
extern int kfunc_def(security_tun_dev_attach_queue)(void *security);
extern int kfunc_def(security_tun_dev_attach)(struct sock *sk, void *security);
extern int kfunc_def(security_tun_dev_open)(void *security);
extern int kfunc_def(security_sctp_assoc_request)(struct sctp_association *asoc, struct sk_buff *skb);
extern int kfunc_def(security_sctp_bind_connect)(struct sock *sk, int optname, struct sockaddr *address, int addrlen);
extern void kfunc_def(security_sctp_sk_clone)(struct sctp_association *asoc, struct sock *sk, struct sock *newsk);
extern int kfunc_def(security_sctp_assoc_established)(struct sctp_association *asoc, struct sk_buff *skb);

// CONFIG_SECURITY_INFINIBAND
extern int kfunc_def(security_ib_pkey_access)(void *sec, u64 subnet_prefix, u16 pkey);
extern int kfunc_def(security_ib_endport_manage_subnet)(void *sec, const char *dev_name, u8 port_num);
extern int kfunc_def(security_ib_alloc_security)(void **sec);
extern void kfunc_def(security_ib_free_security)(void *sec);

// CONFIG_SECURITY_NETWORK_XFRM
extern int kfunc_def(security_xfrm_policy_alloc)(struct xfrm_sec_ctx **ctxp, struct xfrm_user_sec_ctx *sec_ctx,
                                                 gfp_t gfp);
extern int kfunc_def(security_xfrm_policy_clone)(struct xfrm_sec_ctx *old_ctx, struct xfrm_sec_ctx **new_ctxp);
extern void kfunc_def(security_xfrm_policy_free)(struct xfrm_sec_ctx *ctx);
extern int kfunc_def(security_xfrm_policy_delete)(struct xfrm_sec_ctx *ctx);
extern int kfunc_def(security_xfrm_state_alloc)(struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx);
extern int kfunc_def(security_xfrm_state_alloc_acquire)(struct xfrm_state *x, struct xfrm_sec_ctx *polsec, u32 secid);
extern int kfunc_def(security_xfrm_state_delete)(struct xfrm_state *x);
extern void kfunc_def(security_xfrm_state_free)(struct xfrm_state *x);
extern int kfunc_def(security_xfrm_policy_lookup)(struct xfrm_sec_ctx *ctx, u32 fl_secid);
extern int kfunc_def(security_xfrm_state_pol_flow_match)(struct xfrm_state *x, struct xfrm_policy *xp,
                                                         const struct flowi_common *flic);
extern int kfunc_def(security_xfrm_decode_session)(struct sk_buff *skb, u32 *secid);
extern void kfunc_def(security_skb_classify_flow)(struct sk_buff *skb, struct flowi_common *flic);

/* key management security hooks */
// CONFIG_KEYS
typedef void *key_ref_t;
extern int kfunc_def(security_key_alloc)(struct key *key, const struct cred *cred, unsigned long flags);
extern void kfunc_def(security_key_free)(struct key *key);
extern int kfunc_def(security_key_permission)(key_ref_t key_ref, const struct cred *cred, enum key_need_perm need_perm);
extern int kfunc_def(security_key_getsecurity)(struct key *key, char **_buffer);

// CONFIG_AUDIT
extern int kfunc_def(security_audit_rule_init)(u32 field, u32 op, char *rulestr, void **lsmrule);
extern int kfunc_def(security_audit_rule_known)(struct audit_krule *krule);
extern void kfunc_def(security_audit_rule_free)(void *lsmrule);
extern int kfunc_def(security_audit_rule_match)(u32 secid, u32 field, u32 op, void *lsmrule);

// CONFIG_BPF_SYSCALL
extern int kfunc_def(security_bpf)(int cmd, union bpf_attr *attr, unsigned int size);
extern int kfunc_def(security_bpf_map)(struct bpf_map *map, fmode_t fmode);
extern int kfunc_def(security_bpf_prog)(struct bpf_prog *prog);
extern int kfunc_def(security_bpf_map_alloc)(struct bpf_map *map);
extern int kfunc_def(security_bpf_prog_alloc)(struct bpf_prog_aux *aux);
extern void kfunc_def(security_bpf_map_free)(struct bpf_map *map);
extern void kfunc_def(security_bpf_prog_free)(struct bpf_prog_aux *aux);
// CONFIG_BPF_SYSCALL

extern int kfunc_def(security_locked_down)(enum lockdown_reason what);

// CONFIG_PERF_EVENTS
extern int kfunc_def(security_perf_event_open)(struct perf_event_attr *attr, int type);
extern int kfunc_def(security_perf_event_alloc)(struct perf_event *event);
extern void kfunc_def(security_perf_event_free)(struct perf_event *event);
extern int kfunc_def(security_perf_event_read)(struct perf_event *event);
extern int kfunc_def(security_perf_event_write)(struct perf_event *event);

// CONFIG_IO_URING
extern int kfunc_def(security_uring_override_creds)(const struct cred *new);
extern int kfunc_def(security_uring_sqpoll)(void);
extern int kfunc_def(security_uring_cmd)(struct io_uring_cmd *ioucmd);

//
static inline int cap_capable(const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts)
{
    kfunc_call(cap_capable, cred, ns, cap, opts);
    kfunc_not_found();
    return 0;
}
static inline int cap_settime(const struct timespec64 *ts, const struct timezone *tz)
{
    kfunc_call(cap_settime, ts, tz);
    kfunc_not_found();
    return 0;
}
static inline int cap_ptrace_access_check(struct task_struct *child, unsigned int mode)
{
    kfunc_call(cap_ptrace_access_check, child, mode);
    kfunc_not_found();
    return 0;
}
static inline int cap_ptrace_traceme(struct task_struct *parent)
{
    kfunc_call(cap_ptrace_traceme, parent);
    kfunc_not_found();
    return 0;
}
static inline int cap_capget(struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable,
                             kernel_cap_t *permitted)
{
    kfunc_call(cap_capget, target, effective, inheritable, permitted);
    kfunc_not_found();
    return 0;
}
static inline int cap_capset(struct cred *new, const struct cred *old, const kernel_cap_t *effective,
                             const kernel_cap_t *inheritable, const kernel_cap_t *permitted)
{
    kfunc_call(cap_capset, new, old, effective, inheritable, permitted);
    kfunc_not_found();
    return 0;
}
static inline int cap_bprm_creds_from_file(struct linux_binprm *bprm, struct file *file)
{
    kfunc_call(cap_bprm_creds_from_file, bprm, file);
    kfunc_not_found();
    return 0;
}
static inline int cap_inode_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
    kfunc_call(cap_inode_setxattr, dentry, name, value, size, flags);
    kfunc_not_found();
    return 0;
}
static inline int cap_inode_removexattr(struct dentry *dentry, const char *name)
{
    kfunc_call(cap_inode_removexattr, dentry, name);
    kfunc_not_found();
    return 0;
}
static inline int cap_inode_need_killpriv(struct dentry *dentry)
{
    kfunc_call(cap_inode_need_killpriv, dentry);
    kfunc_not_found();
    return 0;
}
static inline int cap_inode_killpriv(struct dentry *dentry)
{
    kfunc_call(cap_inode_killpriv, dentry);
    kfunc_not_found();
    return 0;
}
static inline int cap_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc)
{
    kfunc_call(cap_inode_getsecurity, inode, name, buffer, alloc);
    kfunc_not_found();
    return 0;
}
static inline int cap_mmap_addr(unsigned long addr)
{
    kfunc_call(cap_mmap_addr, addr);
    kfunc_not_found();
    return 0;
}
static inline int cap_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    kfunc_call(cap_mmap_file, file, reqprot, prot, flags);
    kfunc_not_found();
    return 0;
}
static inline int cap_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
    kfunc_call(cap_task_fix_setuid, new, old, flags);
    kfunc_not_found();
    return 0;
}
static inline int cap_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
                                 unsigned long arg5)
{
    kfunc_call(cap_task_prctl, option, arg2, arg3, arg4, arg5);
    kfunc_not_found();
    return 0;
}
static inline int cap_task_setscheduler(struct task_struct *p)
{
    kfunc_call(cap_task_setscheduler, p);
    kfunc_not_found();
    return 0;
}
static inline int cap_task_setioprio(struct task_struct *p, int ioprio)
{
    kfunc_call(cap_task_setioprio, p, ioprio);
    kfunc_not_found();
    return 0;
}
static inline int cap_task_setnice(struct task_struct *p, int nice)
{
    kfunc_call(cap_task_setnice, p, nice);
    kfunc_not_found();
    return 0;
}
static inline int cap_vm_enough_memory(struct mm_struct *mm, long pages)
{
    kfunc_call(cap_vm_enough_memory, mm, pages);
    kfunc_not_found();
    return 0;
}

//

static inline void security_task_getsecid(struct task_struct *task, u32 *secid)
{
    kfunc_call(security_task_getsecid, task, secid);
    kfunc_call(security_task_getsecid_obj, task, secid);
    kfunc_not_found();
}

// When we are uncertain whether secctx exists or is correct, we cannot rely on security_secctx_to_secid; otherwise, secid might be set to an unexpected value.
static inline int security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
    kfunc_call(security_secctx_to_secid, secdata, seclen, secid);
    kfunc_not_found();
    return 0;
}

static inline int security_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
    kfunc_call(security_secid_to_secctx, secid, secdata, seclen);
    kfunc_not_found();
    return 0;
}

static inline void security_release_secctx(char *secdata, u32 seclen)
{
    kfunc_call_void(security_release_secctx, secdata, seclen);
    kfunc_not_found();
}

#endif