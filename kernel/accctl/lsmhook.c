#include "accctl.h"

#include <linux/security.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/errno-base.h>
#include <linux/errno.h>
#include <init/ksyms.h>
#include <hook.h>
#include <log.h>

#define lsm_backup(func) hook_backup(func)
#define lsm_replace(func) hook_replace(func)
#define lsm_call_backup(func, ...) hook_call_backup(func, __VA_ARGS__)
#define lsm_hook(func) hook_kfunc(func)

// todo: Something will be easy if we can geneate a new secctx?

#define lsm_int_hook_before
#define lsm_int_hook_after
#define lsm_void_hook_before
#define lsm_void_hook_after

#define white_cred_before(rc)
#define white_cred_after(rc)

/* Security operations */
int lsm_backup(security_binder_set_context_mgr)(const struct cred *mgr);
int lsm_backup(security_binder_transaction)(const struct cred *from, const struct cred *to);
int lsm_backup(security_binder_transfer_binder)(const struct cred *from, const struct cred *to);
int lsm_backup(security_binder_transfer_file)(const struct cred *from, const struct cred *to, struct file *file);
int lsm_backup(security_ptrace_access_check)(struct task_struct *child, unsigned int mode);
int lsm_backup(security_ptrace_traceme)(struct task_struct *parent);
int lsm_backup(security_capget)(struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable,
                                kernel_cap_t *permitted);
int lsm_backup(security_capset)(struct cred *new, const struct cred *old, const kernel_cap_t *effective,
                                const kernel_cap_t *inheritable, const kernel_cap_t *permitted);
int lsm_backup(security_capable)(const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts);
int lsm_backup(security_quotactl)(int cmds, int type, int id, struct super_block *sb);
int lsm_backup(security_quota_on)(struct dentry *dentry);
int lsm_backup(security_syslog)(int type);
int lsm_backup(security_settime64)(const struct timespec64 *ts, const struct timezone *tz);
int lsm_backup(security_vm_enough_memory_mm)(struct mm_struct *mm, long pages);
int lsm_backup(security_bprm_creds_for_exec)(struct linux_binprm *bprm);
int lsm_backup(security_bprm_creds_from_file)(struct linux_binprm *bprm, struct file *file);
int lsm_backup(security_bprm_check)(struct linux_binprm *bprm);
void lsm_backup(security_bprm_committing_creds)(struct linux_binprm *bprm);
void lsm_backup(security_bprm_committed_creds)(struct linux_binprm *bprm);
int lsm_backup(security_fs_context_dup)(struct fs_context *fc, struct fs_context *src_fc);
int lsm_backup(security_fs_context_parse_param)(struct fs_context *fc, struct fs_parameter *param);
int lsm_backup(security_sb_alloc)(struct super_block *sb);
void lsm_backup(security_sb_delete)(struct super_block *sb);
void lsm_backup(security_sb_free)(struct super_block *sb);
void lsm_backup(security_free_mnt_opts)(void **mnt_opts);
int lsm_backup(security_sb_eat_lsm_opts)(char *options, void **mnt_opts);
int lsm_backup(security_sb_remount)(struct super_block *sb, void *mnt_opts);
int lsm_backup(security_sb_kern_mount)(struct super_block *sb);
int lsm_backup(security_sb_show_options)(struct seq_file *m, struct super_block *sb);
int lsm_backup(security_sb_statfs)(struct dentry *dentry);
int lsm_backup(security_sb_mount)(const char *dev_name, const struct path *path, const char *type, unsigned long flags,
                                  void *data);
int lsm_backup(security_sb_umount)(struct vfsmount *mnt, int flags);
int lsm_backup(security_sb_pivotroot)(const struct path *old_path, const struct path *new_path);
int lsm_backup(security_sb_set_mnt_opts)(struct super_block *sb, void *mnt_opts, unsigned long kern_flags,
                                         unsigned long *set_kern_flags);
int lsm_backup(security_sb_clone_mnt_opts)(const struct super_block *oldsb, struct super_block *newsb,
                                           unsigned long kern_flags, unsigned long *set_kern_flags);
int lsm_backup(security_add_mnt_opt)(const char *option, const char *val, int len, void **mnt_opts);
int lsm_backup(security_move_mount)(const struct path *from_path, const struct path *to_path);
int lsm_backup(security_dentry_init_security)(struct dentry *dentry, int mode, const struct qstr *name, void **ctx,
                                              u32 *ctxlen);
int lsm_backup(security_dentry_create_files_as)(struct dentry *dentry, int mode, struct qstr *name,
                                                const struct cred *old, struct cred *new);

//CONFIG_SECURITY_PATH
int lsm_backup(security_path_unlink)(const struct path *dir, struct dentry *dentry);
int lsm_backup(security_path_mkdir)(const struct path *dir, struct dentry *dentry, umode_t mode);
int lsm_backup(security_path_rmdir)(const struct path *dir, struct dentry *dentry);
int lsm_backup(security_path_mknod)(const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev);
int lsm_backup(security_path_truncate)(const struct path *path);
int lsm_backup(security_path_symlink)(const struct path *dir, struct dentry *dentry, const char *old_name);
int lsm_backup(security_path_link)(struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry);
int lsm_backup(security_path_rename)(const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir,
                                     struct dentry *new_dentry, unsigned int flags);
int lsm_backup(security_path_chmod)(const struct path *path, umode_t mode);
int lsm_backup(security_path_chown)(const struct path *path, kuid_t uid, kgid_t gid);
int lsm_backup(security_path_chroot)(const struct path *path);
/* CONFIG_SECURITY_PATH */

/* Needed for inode based security check */
int lsm_backup(security_path_notify)(const struct path *path, u64 mask, unsigned int obj_type);
int lsm_backup(security_inode_alloc)(struct inode *inode);
void lsm_backup(security_inode_free)(struct inode *inode);
int lsm_backup(security_inode_init_security)(struct inode *inode, struct inode *dir, const struct qstr *qstr,
                                             initxattrs initxattrs, void *fs_data);
int lsm_backup(security_old_inode_init_security)(struct inode *inode, struct inode *dir, const struct qstr *qstr,
                                                 const char **name, void **value, size_t *len);
int lsm_backup(security_inode_create)(struct inode *dir, struct dentry *dentry, umode_t mode);
int lsm_backup(security_inode_link)(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);
int lsm_backup(security_inode_unlink)(struct inode *dir, struct dentry *dentry);
int lsm_backup(security_inode_symlink)(struct inode *dir, struct dentry *dentry, const char *old_name);
int lsm_backup(security_inode_mkdir)(struct inode *dir, struct dentry *dentry, umode_t mode);
int lsm_backup(security_inode_rmdir)(struct inode *dir, struct dentry *dentry);
int lsm_backup(security_inode_mknod)(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev);
int lsm_backup(security_inode_rename)(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
                                      struct dentry *new_dentry, unsigned int flags);
int lsm_backup(security_inode_readlink)(struct dentry *dentry);
int lsm_backup(security_inode_follow_link)(struct dentry *dentry, struct inode *inode, bool rcu);
int lsm_backup(security_inode_permission)(struct inode *inode, int mask);
int lsm_backup(security_inode_setattr)(struct dentry *dentry, struct iattr *attr);
int lsm_backup(security_inode_getattr)(const struct path *path);
int lsm_backup(security_inode_setxattr)(struct dentry *dentry, const char *name, const void *value, size_t size,
                                        int flags);
void lsm_backup(security_inode_post_setxattr)(struct dentry *dentry, const char *name, const void *value, size_t size,
                                              int flags);
int lsm_backup(security_inode_getxattr)(struct dentry *dentry, const char *name);
int lsm_backup(security_inode_listxattr)(struct dentry *dentry);
int lsm_backup(security_inode_removexattr)(struct dentry *dentry, const char *name);
int lsm_backup(security_inode_set_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name,
                                       struct posix_acl *kacl);
int lsm_backup(security_inode_get_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name);
int lsm_backup(security_inode_remove_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name);
int lsm_backup(security_inode_need_killpriv)(struct dentry *dentry);
int lsm_backup(security_inode_killpriv)(struct dentry *dentry);
int lsm_backup(security_inode_getsecurity)(struct inode *inode, const char *name, void **buffer, bool alloc);
int lsm_backup(security_inode_setsecurity)(struct inode *inode, const char *name, const void *value, size_t size,
                                           int flags);
int lsm_backup(security_inode_listsecurity)(struct inode *inode, char *buffer, size_t buffer_size);
void lsm_backup(security_inode_getsecid)(struct inode *inode, u32 *secid);
int lsm_backup(security_inode_copy_up)(struct dentry *src, struct cred **new);
int lsm_backup(security_inode_copy_up_xattr)(const char *name);
int lsm_backup(security_kernfs_init_security)(struct kernfs_node *kn_dir, struct kernfs_node *kn);
int lsm_backup(security_file_permission)(struct file *file, int mask);
int lsm_backup(security_file_alloc)(struct file *file);
void lsm_backup(security_file_free)(struct file *file);
int lsm_backup(security_file_ioctl)(struct file *file, unsigned int cmd, unsigned long arg);
int lsm_backup(security_mmap_addr)(unsigned long addr);
int lsm_backup(security_mmap_file)(struct file *file, unsigned long prot, unsigned long flags);
int lsm_backup(security_file_mprotect)(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot);
int lsm_backup(security_file_lock)(struct file *file, unsigned int cmd);
int lsm_backup(security_file_fcntl)(struct file *file, unsigned int cmd, unsigned long arg);
void lsm_backup(security_file_set_fowner)(struct file *file);
int lsm_backup(security_file_send_sigiotask)(struct task_struct *tsk, struct fown_struct *fown, int sig);
int lsm_backup(security_file_receive)(struct file *file);
// int lsm_backup(security_file_open)(struct file *file);
int lsm_backup(security_file_open)(struct file *file, const struct cred *cred);
int lsm_backup(security_file_truncate)(struct file *file);
int lsm_backup(security_task_alloc)(struct task_struct *task, unsigned long clone_flags);
void lsm_backup(security_task_free)(struct task_struct *task);
int lsm_backup(security_cred_alloc_blank)(struct cred *cred, gfp_t gfp);
void lsm_backup(security_cred_free)(struct cred *cred);
int lsm_backup(security_prepare_creds)(struct cred *new, const struct cred *old, gfp_t gfp);
void lsm_backup(security_transfer_creds)(struct cred *new, const struct cred *old);
void lsm_backup(security_cred_getsecid)(const struct cred *c, u32 *secid);
int lsm_backup(security_kernel_act_as)(struct cred *new, u32 secid);
int lsm_backup(security_kernel_create_files_as)(struct cred *new, struct inode *inode);
int lsm_backup(security_kernel_module_request)(char *kmod_name);
int lsm_backup(security_kernel_load_data)(enum kernel_load_data_id id, bool contents);
int lsm_backup(security_kernel_post_load_data)(char *buf, loff_t size, enum kernel_load_data_id id, char *description);
int lsm_backup(security_kernel_read_file)(struct file *file, enum kernel_read_file_id id, bool contents);
int lsm_backup(security_kernel_post_read_file)(struct file *file, char *buf, loff_t size, enum kernel_read_file_id id);
int lsm_backup(security_task_fix_setuid)(struct cred *new, const struct cred *old, int flags);
int lsm_backup(security_task_fix_setgid)(struct cred *new, const struct cred *old, int flags);
int lsm_backup(security_task_fix_setgroups)(struct cred *new, const struct cred *old);
int lsm_backup(security_task_setpgid)(struct task_struct *p, pid_t pgid);
int lsm_backup(security_task_getpgid)(struct task_struct *p);
int lsm_backup(security_task_getsid)(struct task_struct *p);
void lsm_backup(security_current_getsecid_subj)(u32 *secid);
void lsm_backup(security_task_getsecid_obj)(struct task_struct *p, u32 *secid); // ?-6.3
void lsm_backup(security_task_getsecid)(struct task_struct *p, u32 *secid); // 4.4-?
int lsm_backup(security_task_setnice)(struct task_struct *p, int nice);
int lsm_backup(security_task_setioprio)(struct task_struct *p, int ioprio);
int lsm_backup(security_task_getioprio)(struct task_struct *p);
int lsm_backup(security_task_prlimit)(const struct cred *cred, const struct cred *tcred, unsigned int flags);
int lsm_backup(security_task_setrlimit)(struct task_struct *p, unsigned int resource, struct rlimit *new_rlim);
int lsm_backup(security_task_setscheduler)(struct task_struct *p);
int lsm_backup(security_task_getscheduler)(struct task_struct *p);
int lsm_backup(security_task_movememory)(struct task_struct *p);
int lsm_backup(security_task_kill)(struct task_struct *p, struct kernel_siginfo *info, int sig,
                                   const struct cred *cred);
int lsm_backup(security_task_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
                                    unsigned long arg5);
void lsm_backup(security_task_to_inode)(struct task_struct *p, struct inode *inode);
int lsm_backup(security_create_user_ns)(const struct cred *cred);
int lsm_backup(security_ipc_permission)(struct kern_ipc_perm *ipcp, short flag);
void lsm_backup(security_ipc_getsecid)(struct kern_ipc_perm *ipcp, u32 *secid);
int lsm_backup(security_msg_msg_alloc)(struct msg_msg *msg);
void lsm_backup(security_msg_msg_free)(struct msg_msg *msg);
int lsm_backup(security_msg_queue_alloc)(struct kern_ipc_perm *msq);
void lsm_backup(security_msg_queue_free)(struct kern_ipc_perm *msq);
int lsm_backup(security_msg_queue_associate)(struct kern_ipc_perm *msq, int msqflg);
int lsm_backup(security_msg_queue_msgctl)(struct kern_ipc_perm *msq, int cmd);
int lsm_backup(security_msg_queue_msgsnd)(struct kern_ipc_perm *msq, struct msg_msg *msg, int msqflg);
int lsm_backup(security_msg_queue_msgrcv)(struct kern_ipc_perm *msq, struct msg_msg *msg, struct task_struct *target,
                                          long type, int mode);
int lsm_backup(security_shm_alloc)(struct kern_ipc_perm *shp);
void lsm_backup(security_shm_free)(struct kern_ipc_perm *shp);
int lsm_backup(security_shm_associate)(struct kern_ipc_perm *shp, int shmflg);
int lsm_backup(security_shm_shmctl)(struct kern_ipc_perm *shp, int cmd);
int lsm_backup(security_shm_shmat)(struct kern_ipc_perm *shp, char __user *shmaddr, int shmflg);
int lsm_backup(security_sem_alloc)(struct kern_ipc_perm *sma);
void lsm_backup(security_sem_free)(struct kern_ipc_perm *sma);
int lsm_backup(security_sem_associate)(struct kern_ipc_perm *sma, int semflg);
int lsm_backup(security_sem_semctl)(struct kern_ipc_perm *sma, int cmd);
int lsm_backup(security_sem_semop)(struct kern_ipc_perm *sma, struct sembuf *sops, unsigned nsops, int alter);
void lsm_backup(security_d_instantiate)(struct dentry *dentry, struct inode *inode);
int lsm_backup(security_getprocattr)(struct task_struct *p, const char *lsm, char *name, char **value);
int lsm_backup(security_setprocattr)(const char *lsm, const char *name, void *value, size_t size);
int lsm_backup(security_netlink_send)(struct sock *sk, struct sk_buff *skb);
int lsm_backup(security_ismaclabel)(const char *name);
int lsm_backup(security_secid_to_secctx)(u32 secid, char **secdata, u32 *seclen);
int lsm_backup(security_secctx_to_secid)(const char *secdata, u32 seclen, u32 *secid);
void lsm_backup(security_release_secctx)(char *secdata, u32 seclen);
void lsm_backup(security_inode_invalidate_secctx)(struct inode *inode);
int lsm_backup(security_inode_notifysecctx)(struct inode *inode, void *ctx, u32 ctxlen);
int lsm_backup(security_inode_setsecctx)(struct dentry *dentry, void *ctx, u32 ctxlen);
int lsm_backup(security_inode_getsecctx)(struct inode *inode, void **ctx, u32 *ctxlen);

// CONFIG_WATCH_QUEUE
int lsm_backup(security_post_notification)(const struct cred *w_cred, const struct cred *cred,
                                           struct watch_notification *n);

// CONFIG_KEY_NOTIFICATIONS
int lsm_backup(security_watch_key)(struct key *key);

// CONFIG_SECURITY_NETWORK
int lsm_backup(security_unix_stream_connect)(struct sock *sock, struct sock *other, struct sock *newsk);
int lsm_backup(security_unix_may_send)(struct socket *sock, struct socket *other);
int lsm_backup(security_socket_create)(int family, int type, int protocol, int kern);
int lsm_backup(security_socket_post_create)(struct socket *sock, int family, int type, int protocol, int kern);
int lsm_backup(security_socket_socketpair)(struct socket *socka, struct socket *sockb);
int lsm_backup(security_socket_bind)(struct socket *sock, struct sockaddr *address, int addrlen);
int lsm_backup(security_socket_connect)(struct socket *sock, struct sockaddr *address, int addrlen);
int lsm_backup(security_socket_listen)(struct socket *sock, int backlog);
int lsm_backup(security_socket_accept)(struct socket *sock, struct socket *newsock);
int lsm_backup(security_socket_sendmsg)(struct socket *sock, struct msghdr *msg, int size);
int lsm_backup(security_socket_recvmsg)(struct socket *sock, struct msghdr *msg, int size, int flags);
int lsm_backup(security_socket_getsockname)(struct socket *sock);
int lsm_backup(security_socket_getpeername)(struct socket *sock);
int lsm_backup(security_socket_getsockopt)(struct socket *sock, int level, int optname);
int lsm_backup(security_socket_setsockopt)(struct socket *sock, int level, int optname);
int lsm_backup(security_socket_shutdown)(struct socket *sock, int how);
int lsm_backup(security_sock_rcv_skb)(struct sock *sk, struct sk_buff *skb);
int lsm_backup(security_socket_getpeersec_stream)(struct socket *sock, sockptr_t optval, sockptr_t optlen,
                                                  unsigned int len);
int lsm_backup(security_socket_getpeersec_dgram)(struct socket *sock, struct sk_buff *skb, u32 *secid);
int lsm_backup(security_sk_alloc)(struct sock *sk, int family, gfp_t priority);
void lsm_backup(security_sk_free)(struct sock *sk);
void lsm_backup(security_sk_clone)(const struct sock *sk, struct sock *newsk);
void lsm_backup(security_sk_classify_flow)(struct sock *sk, struct flowi_common *flic);
void lsm_backup(security_req_classify_flow)(const struct request_sock *req, struct flowi_common *flic);
void lsm_backup(security_sock_graft)(struct sock *sk, struct socket *parent);
int lsm_backup(security_inet_conn_request)(const struct sock *sk, struct sk_buff *skb, struct request_sock *req);
void lsm_backup(security_inet_csk_clone)(struct sock *newsk, const struct request_sock *req);
void lsm_backup(security_inet_conn_established)(struct sock *sk, struct sk_buff *skb);
int lsm_backup(security_secmark_relabel_packet)(u32 secid);
void lsm_backup(security_secmark_refcount_inc)(void);
void lsm_backup(security_secmark_refcount_dec)(void);
int lsm_backup(security_tun_dev_alloc_security)(void **security);
void lsm_backup(security_tun_dev_free_security)(void *security);
int lsm_backup(security_tun_dev_create)(void);
int lsm_backup(security_tun_dev_attach_queue)(void *security);
int lsm_backup(security_tun_dev_attach)(struct sock *sk, void *security);
int lsm_backup(security_tun_dev_open)(void *security);
int lsm_backup(security_sctp_assoc_request)(struct sctp_association *asoc, struct sk_buff *skb);
int lsm_backup(security_sctp_bind_connect)(struct sock *sk, int optname, struct sockaddr *address, int addrlen);
void lsm_backup(security_sctp_sk_clone)(struct sctp_association *asoc, struct sock *sk, struct sock *newsk);
int lsm_backup(security_sctp_assoc_established)(struct sctp_association *asoc, struct sk_buff *skb);

// CONFIG_SECURITY_INFINIBAND
int lsm_backup(security_ib_pkey_access)(void *sec, u64 subnet_prefix, u16 pkey);
int lsm_backup(security_ib_endport_manage_subnet)(void *sec, const char *dev_name, u8 port_num);
int lsm_backup(security_ib_alloc_security)(void **sec);
void lsm_backup(security_ib_free_security)(void *sec);

// CONFIG_SECURITY_NETWORK_XFRM
int lsm_backup(security_xfrm_policy_alloc)(struct xfrm_sec_ctx **ctxp, struct xfrm_user_sec_ctx *sec_ctx, gfp_t gfp);
int lsm_backup(security_xfrm_policy_clone)(struct xfrm_sec_ctx *old_ctx, struct xfrm_sec_ctx **new_ctxp);
void lsm_backup(security_xfrm_policy_free)(struct xfrm_sec_ctx *ctx);
int lsm_backup(security_xfrm_policy_delete)(struct xfrm_sec_ctx *ctx);
int lsm_backup(security_xfrm_state_alloc)(struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx);
int lsm_backup(security_xfrm_state_alloc_acquire)(struct xfrm_state *x, struct xfrm_sec_ctx *polsec, u32 secid);
int lsm_backup(security_xfrm_state_delete)(struct xfrm_state *x);
void lsm_backup(security_xfrm_state_free)(struct xfrm_state *x);
int lsm_backup(security_xfrm_policy_lookup)(struct xfrm_sec_ctx *ctx, u32 fl_secid);
int lsm_backup(security_xfrm_state_pol_flow_match)(struct xfrm_state *x, struct xfrm_policy *xp,
                                                   const struct flowi_common *flic);
int lsm_backup(security_xfrm_decode_session)(struct sk_buff *skb, u32 *secid);
void lsm_backup(security_skb_classify_flow)(struct sk_buff *skb, struct flowi_common *flic);

/* key management security hooks */
// CONFIG_KEYS
typedef void *key_ref_t;
int lsm_backup(security_key_alloc)(struct key *key, const struct cred *cred, unsigned long flags);
void lsm_backup(security_key_free)(struct key *key);
int lsm_backup(security_key_permission)(key_ref_t key_ref, const struct cred *cred, enum key_need_perm need_perm);
int lsm_backup(security_key_getsecurity)(struct key *key, char **_buffer);

// CONFIG_AUDIT
int lsm_backup(security_audit_rule_init)(u32 field, u32 op, char *rulestr, void **lsmrule);
int lsm_backup(security_audit_rule_known)(struct audit_krule *krule);
void lsm_backup(security_audit_rule_free)(void *lsmrule);
int lsm_backup(security_audit_rule_match)(u32 secid, u32 field, u32 op, void *lsmrule);

// CONFIG_BPF_SYSCALL
int lsm_backup(security_bpf)(int cmd, union bpf_attr *attr, unsigned int size);
int lsm_backup(security_bpf_map)(struct bpf_map *map, fmode_t fmode);
int lsm_backup(security_bpf_prog)(struct bpf_prog *prog);
int lsm_backup(security_bpf_map_alloc)(struct bpf_map *map);
int lsm_backup(security_bpf_prog_alloc)(struct bpf_prog_aux *aux);
void lsm_backup(security_bpf_map_free)(struct bpf_map *map);
void lsm_backup(security_bpf_prog_free)(struct bpf_prog_aux *aux);
// CONFIG_BPF_SYSCALL

int lsm_backup(security_locked_down)(enum lockdown_reason what);

// CONFIG_PERF_EVENTS
int lsm_backup(security_perf_event_open)(struct perf_event_attr *attr, int type);
int lsm_backup(security_perf_event_alloc)(struct perf_event *event);
void lsm_backup(security_perf_event_free)(struct perf_event *event);
int lsm_backup(security_perf_event_read)(struct perf_event *event);
int lsm_backup(security_perf_event_write)(struct perf_event *event);

// CONFIG_IO_URING
int lsm_backup(security_uring_override_creds)(const struct cred *new);
int lsm_backup(security_uring_sqpoll)(void);
int lsm_backup(security_uring_cmd)(struct io_uring_cmd *ioucmd);

/* Security operations */

int lsm_replace(security_binder_set_context_mgr)(const struct cred *mgr)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_binder_set_context_mgr, mgr);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_binder_transaction)(const struct cred *from, const struct cred *to)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_binder_transaction, from, to);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_binder_transfer_binder)(const struct cred *from, const struct cred *to)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_binder_transfer_binder, from, to);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_binder_transfer_file)(const struct cred *from, const struct cred *to, struct file *file)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_binder_transfer_file, from, to, file);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_ptrace_access_check)(struct task_struct *child, unsigned int mode)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_ptrace_access_check, child, mode);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_ptrace_traceme)(struct task_struct *parent)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_ptrace_traceme, parent);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_capget)(struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable,
                                 kernel_cap_t *permitted)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_capget, target, effective, inheritable, permitted);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_capset)(struct cred *new, const struct cred *old, const kernel_cap_t *effective,
                                 const kernel_cap_t *inheritable, const kernel_cap_t *permitted)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_capset, new, old, effective, inheritable, permitted);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_capable)(const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_capable, cred, ns, cap, opts);
    white_cred_after(0);
    lsm_int_hook_after;

    return ret;
}
int lsm_replace(security_quotactl)(int cmds, int type, int id, struct super_block *sb)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_quotactl, cmds, type, id, sb);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_quota_on)(struct dentry *dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_quota_on, dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_syslog)(int type)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_syslog, type);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_settime64)(const struct timespec64 *ts, const struct timezone *tz)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_settime64, ts, tz);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_vm_enough_memory_mm)(struct mm_struct *mm, long pages)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_vm_enough_memory_mm, mm, pages);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// todo
int lsm_replace(security_bprm_creds_for_exec)(struct linux_binprm *bprm)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_bprm_creds_for_exec, bprm);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// todo
int lsm_replace(security_bprm_creds_from_file)(struct linux_binprm *bprm, struct file *file)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_bprm_creds_from_file, bprm, file);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// todo
int lsm_replace(security_bprm_check)(struct linux_binprm *bprm)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_bprm_check, bprm);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

void lsm_replace(security_bprm_committing_creds)(struct linux_binprm *bprm)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_bprm_committing_creds, bprm);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_bprm_committed_creds)(struct linux_binprm *bprm)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_bprm_committed_creds, bprm);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_fs_context_dup)(struct fs_context *fc, struct fs_context *src_fc)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_fs_context_dup, fc, src_fc);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
// 111
int lsm_replace(security_fs_context_parse_param)(struct fs_context *fc, struct fs_parameter *param)
{
    // int defrc = -ENOPARAM;
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_fs_context_parse_param, fc, param);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sb_alloc)(struct super_block *sb)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_alloc, sb);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_sb_delete)(struct super_block *sb)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_sb_delete, sb);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_sb_free)(struct super_block *sb)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_sb_free, sb);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_free_mnt_opts)(void **mnt_opts)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_free_mnt_opts, mnt_opts);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_sb_eat_lsm_opts)(char *options, void **mnt_opts)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_eat_lsm_opts, options, mnt_opts);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sb_remount)(struct super_block *sb, void *mnt_opts)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_remount, sb, mnt_opts);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sb_kern_mount)(struct super_block *sb)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_kern_mount, sb);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sb_show_options)(struct seq_file *m, struct super_block *sb)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_show_options, m, sb);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sb_statfs)(struct dentry *dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_statfs, dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sb_mount)(const char *dev_name, const struct path *path, const char *type, unsigned long flags,
                                   void *data)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_mount, dev_name, path, type, flags, data);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sb_umount)(struct vfsmount *mnt, int flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_umount, mnt, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sb_pivotroot)(const struct path *old_path, const struct path *new_path)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_pivotroot, old_path, new_path);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sb_set_mnt_opts)(struct super_block *sb, void *mnt_opts, unsigned long kern_flags,
                                          unsigned long *set_kern_flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_set_mnt_opts, sb, mnt_opts, kern_flags, set_kern_flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sb_clone_mnt_opts)(const struct super_block *oldsb, struct super_block *newsb,
                                            unsigned long kern_flags, unsigned long *set_kern_flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sb_clone_mnt_opts, oldsb, newsb, kern_flags, set_kern_flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_add_mnt_opt)(const char *option, const char *val, int len, void **mnt_opts)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_add_mnt_opt, option, val, len, mnt_opts);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_move_mount)(const struct path *from_path, const struct path *to_path)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_move_mount, from_path, to_path);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_dentry_init_security)(struct dentry *dentry, int mode, const struct qstr *name, void **ctx,
                                               u32 *ctxlen)
{
    // int defrc = -EOPNOTSUPP;
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_dentry_init_security, dentry, mode, name, ctx, ctxlen);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_dentry_create_files_as)(struct dentry *dentry, int mode, struct qstr *name,
                                                 const struct cred *old, struct cred *new)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_dentry_create_files_as, dentry, mode, name, old, new);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

//CONFIG_SECURITY_PATH
int lsm_replace(security_path_unlink)(const struct path *dir, struct dentry *dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_unlink, dir, dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_path_mkdir)(const struct path *dir, struct dentry *dentry, umode_t mode)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_mkdir, dir, dentry, mode);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_path_rmdir)(const struct path *dir, struct dentry *dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_rmdir, dir, dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_path_mknod)(const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_mknod, dir, dentry, mode, dev);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_path_truncate)(const struct path *path)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_truncate, path);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_path_symlink)(const struct path *dir, struct dentry *dentry, const char *old_name)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_symlink, dir, dentry, old_name);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_path_link)(struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_link, old_dentry, new_dir, new_dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_path_rename)(const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir,
                                      struct dentry *new_dentry, unsigned int flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_rename, old_dir, old_dentry, new_dir, new_dentry, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_path_chmod)(const struct path *path, umode_t mode)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_chmod, path, mode);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_path_chown)(const struct path *path, kuid_t uid, kgid_t gid)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_chown, path, uid, gid);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_path_chroot)(const struct path *path)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_chroot, path);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
/* CONFIG_SECURITY_PATH */

/* Needed for inode based security check */
int lsm_replace(security_path_notify)(const struct path *path, u64 mask, unsigned int obj_type)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_path_notify, path, mask, obj_type);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_alloc)(struct inode *inode)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_alloc, inode);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_inode_free)(struct inode *inode)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_inode_free, inode);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_inode_init_security)(struct inode *inode, struct inode *dir, const struct qstr *qstr,
                                              initxattrs initxattrs, void *fs_data)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_init_security, inode, dir, qstr, initxattrs, fs_data);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_old_inode_init_security)(struct inode *inode, struct inode *dir, const struct qstr *qstr,
                                                  const char **name, void **value, size_t *len)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_old_inode_init_security, inode, dir, qstr, name, value, len);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_create)(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_create, dir, dentry, mode);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_link)(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_link, old_dentry, dir, new_dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_unlink)(struct inode *dir, struct dentry *dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_unlink, dir, dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_symlink)(struct inode *dir, struct dentry *dentry, const char *old_name)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_symlink, dir, dentry, old_name);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_mkdir)(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_mkdir, dir, dentry, mode);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_rmdir)(struct inode *dir, struct dentry *dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_rmdir, dir, dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_mknod)(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_mknod, dir, dentry, mode, dev);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_rename)(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
                                       struct dentry *new_dentry, unsigned int flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_rename, old_dir, old_dentry, new_dir, new_dentry, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_readlink)(struct dentry *dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_readlink, dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_follow_link)(struct dentry *dentry, struct inode *inode, bool rcu)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_follow_link, dentry, inode, rcu);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_permission)(struct inode *inode, int mask)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_permission, inode, mask);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_setattr)(struct dentry *dentry, struct iattr *attr)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_setattr, dentry, attr);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_getattr)(const struct path *path)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_getattr, path);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_setxattr)(struct dentry *dentry, const char *name, const void *value, size_t size,
                                         int flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_setxattr, dentry, name, value, size, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_inode_post_setxattr)(struct dentry *dentry, const char *name, const void *value, size_t size,
                                               int flags)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_inode_post_setxattr, dentry, name, value, size, flags);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_inode_getxattr)(struct dentry *dentry, const char *name)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_getxattr, dentry, name);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_listxattr)(struct dentry *dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_listxattr, dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_removexattr)(struct dentry *dentry, const char *name)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_removexattr, dentry, name);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_set_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name,
                                        struct posix_acl *kacl)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_set_acl, idmap, dentry, acl_name, kacl);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_get_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_get_acl, idmap, dentry, acl_name);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_remove_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_remove_acl, idmap, dentry, acl_name);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_need_killpriv)(struct dentry *dentry)
{
    lsm_int_hook_before;
    // white_cred_before(0);
    int ret = lsm_call_backup(security_inode_need_killpriv, dentry);
    // white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_killpriv)(struct dentry *dentry)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_killpriv, dentry);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_getsecurity)(struct inode *inode, const char *name, void **buffer, bool alloc)
{
    // int defrc = -EOPNOTSUPP;
    lsm_int_hook_before;
    // white_cred_before(0);
    int ret = lsm_call_backup(security_inode_getsecurity, inode, name, buffer, alloc);
    // white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_setsecurity)(struct inode *inode, const char *name, const void *value, size_t size,
                                            int flags)
{
    // int defrc = -EOPNOTSUPP;
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_setsecurity, inode, name, value, size, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_listsecurity)(struct inode *inode, char *buffer, size_t buffer_size)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_listsecurity, inode, buffer, buffer_size);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_inode_getsecid)(struct inode *inode, u32 *secid)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_inode_getsecid, inode, secid);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_inode_copy_up)(struct dentry *src, struct cred **new)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_copy_up, src, new);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_copy_up_xattr)(const char *name)
{
    // // int defrc = -EOPNOTSUPP;
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_copy_up_xattr, name);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_kernfs_init_security)(struct kernfs_node *kn_dir, struct kernfs_node *kn)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_kernfs_init_security, kn_dir, kn);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_file_permission)(struct file *file, int mask)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_file_permission, file, mask);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_file_alloc)(struct file *file)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_file_alloc, file);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_file_free)(struct file *file)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_file_free, file);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_file_ioctl)(struct file *file, unsigned int cmd, unsigned long arg)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_file_ioctl, file, cmd, arg);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_mmap_addr)(unsigned long addr)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_mmap_addr, addr);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_mmap_file)(struct file *file, unsigned long prot, unsigned long flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_mmap_file, file, prot, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_file_mprotect)(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_file_mprotect, vma, reqprot, prot);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_file_lock)(struct file *file, unsigned int cmd)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_file_lock, file, cmd);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_file_fcntl)(struct file *file, unsigned int cmd, unsigned long arg)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_file_fcntl, file, cmd, arg);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_file_set_fowner)(struct file *file)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_file_set_fowner, file);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_file_send_sigiotask)(struct task_struct *tsk, struct fown_struct *fown, int sig)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_file_send_sigiotask, tsk, fown, sig);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_file_receive)(struct file *file)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_file_receive, file);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_file_open)(struct file *file, const struct cred *cred)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_file_open, file, cred);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_file_truncate)(struct file *file)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_file_truncate, file);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_alloc)(struct task_struct *task, unsigned long clone_flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_alloc, task, clone_flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_task_free)(struct task_struct *task)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_task_free, task);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_cred_alloc_blank)(struct cred *cred, gfp_t gfp)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_cred_alloc_blank, cred, gfp);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_cred_free)(struct cred *cred)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_cred_free, cred);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_prepare_creds)(struct cred *new, const struct cred *old, gfp_t gfp)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_prepare_creds, new, old, gfp);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_transfer_creds)(struct cred *new, const struct cred *old)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_transfer_creds, new, old);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_cred_getsecid)(const struct cred *c, u32 *secid)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_cred_getsecid, c, secid);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_kernel_act_as)(struct cred *new, u32 secid)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_kernel_act_as, new, secid);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_kernel_create_files_as)(struct cred *new, struct inode *inode)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_kernel_create_files_as, new, inode);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_kernel_module_request)(char *kmod_name)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_kernel_module_request, kmod_name);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_kernel_load_data)(enum kernel_load_data_id id, bool contents)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_kernel_load_data, id, contents);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_kernel_post_load_data)(char *buf, loff_t size, enum kernel_load_data_id id, char *description)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_kernel_post_load_data, buf, size, id, description);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_kernel_read_file)(struct file *file, enum kernel_read_file_id id, bool contents)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_kernel_read_file, file, id, contents);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_kernel_post_read_file)(struct file *file, char *buf, loff_t size, enum kernel_read_file_id id)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_kernel_post_read_file, file, buf, size, id);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_fix_setuid)(struct cred *new, const struct cred *old, int flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_fix_setuid, new, old, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_fix_setgid)(struct cred *new, const struct cred *old, int flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_fix_setgid, new, old, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_fix_setgroups)(struct cred *new, const struct cred *old)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_fix_setgroups, new, old);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_setpgid)(struct task_struct *p, pid_t pgid)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_setpgid, p, pgid);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_getpgid)(struct task_struct *p)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_getpgid, p);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_getsid)(struct task_struct *p)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_getsid, p);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_current_getsecid_subj)(u32 *secid)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_current_getsecid_subj, secid);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_task_getsecid_obj)(struct task_struct *p, u32 *secid) // ?-6.3
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_task_getsecid_obj, p, secid);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_task_getsecid)(struct task_struct *p, u32 *secid) // 4.4-?
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_task_getsecid, p, secid);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_task_setnice)(struct task_struct *p, int nice)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_setnice, p, nice);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_setioprio)(struct task_struct *p, int ioprio)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_setioprio, p, ioprio);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_getioprio)(struct task_struct *p)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_getioprio, p);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_prlimit)(const struct cred *cred, const struct cred *tcred, unsigned int flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_prlimit, cred, tcred, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_setrlimit)(struct task_struct *p, unsigned int resource, struct rlimit *new_rlim)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_setrlimit, p, resource, new_rlim);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_setscheduler)(struct task_struct *p)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_setscheduler, p);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_getscheduler)(struct task_struct *p)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_getscheduler, p);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_movememory)(struct task_struct *p)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_movememory, p);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_kill)(struct task_struct *p, struct kernel_siginfo *info, int sig,
                                    const struct cred *cred)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_task_kill, p, info, sig, cred);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_task_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
                                     unsigned long arg5)
{
    // int defrc = -ENOSYS;
    lsm_int_hook_before;
    // white_cred_before(0);
    int ret = lsm_call_backup(security_task_prctl, option, arg2, arg3, arg4, arg5);
    // white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_task_to_inode)(struct task_struct *p, struct inode *inode)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_task_to_inode, p, inode);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_create_user_ns)(const struct cred *cred)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_create_user_ns, cred);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_ipc_permission)(struct kern_ipc_perm *ipcp, short flag)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_ipc_permission, ipcp, flag);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_ipc_getsecid)(struct kern_ipc_perm *ipcp, u32 *secid)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_ipc_getsecid, ipcp, secid);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_msg_msg_alloc)(struct msg_msg *msg)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_msg_msg_alloc, msg);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_msg_msg_free)(struct msg_msg *msg)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_msg_msg_free, msg);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_msg_queue_alloc)(struct kern_ipc_perm *msq)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_msg_queue_alloc, msq);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_msg_queue_free)(struct kern_ipc_perm *msq)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_msg_queue_free, msq);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_msg_queue_associate)(struct kern_ipc_perm *msq, int msqflg)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_msg_queue_associate, msq, msqflg);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_msg_queue_msgctl)(struct kern_ipc_perm *msq, int cmd)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_msg_queue_msgctl, msq, cmd);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_msg_queue_msgsnd)(struct kern_ipc_perm *msq, struct msg_msg *msg, int msqflg)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_msg_queue_msgsnd, msq, msg, msqflg);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_msg_queue_msgrcv)(struct kern_ipc_perm *msq, struct msg_msg *msg, struct task_struct *target,
                                           long type, int mode)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_msg_queue_msgrcv, msq, msg, target, type, mode);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_shm_alloc)(struct kern_ipc_perm *shp)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_shm_alloc, shp);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_shm_free)(struct kern_ipc_perm *shp)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_shm_free, shp);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_shm_associate)(struct kern_ipc_perm *shp, int shmflg)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_shm_associate, shp, shmflg);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_shm_shmctl)(struct kern_ipc_perm *shp, int cmd)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_shm_shmctl, shp, cmd);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_shm_shmat)(struct kern_ipc_perm *shp, char __user *shmaddr, int shmflg)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_shm_shmat, shp, shmaddr, shmflg);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sem_alloc)(struct kern_ipc_perm *sma)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sem_alloc, sma);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_sem_free)(struct kern_ipc_perm *sma)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_sem_free, sma);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_sem_associate)(struct kern_ipc_perm *sma, int semflg)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sem_associate, sma, semflg);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sem_semctl)(struct kern_ipc_perm *sma, int cmd)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sem_semctl, sma, cmd);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sem_semop)(struct kern_ipc_perm *sma, struct sembuf *sops, unsigned nsops, int alter)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sem_semop, sma, sops, nsops, alter);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_d_instantiate)(struct dentry *dentry, struct inode *inode)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_d_instantiate, dentry, inode);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_getprocattr)(struct task_struct *p, const char *lsm, char *name, char **value)
{
    // int defrc = -EINVAL;
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_getprocattr, p, lsm, name, value);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_setprocattr)(const char *lsm, const char *name, void *value, size_t size)
{
    // int defrc = -EINVAL;
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_setprocattr, lsm, name, value, size);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_netlink_send)(struct sock *sk, struct sk_buff *skb)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_netlink_send, sk, skb);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_ismaclabel)(const char *name)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_ismaclabel, name);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_secid_to_secctx)(u32 secid, char **secdata, u32 *seclen)
{
    // int defrc = -EOPNOTSUPP;
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_secid_to_secctx, secid, secdata, seclen);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_secctx_to_secid)(const char *secdata, u32 seclen, u32 *secid)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_secctx_to_secid, secdata, seclen, secid);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_release_secctx)(char *secdata, u32 seclen)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_release_secctx, secdata, seclen);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_inode_invalidate_secctx)(struct inode *inode)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_inode_invalidate_secctx, inode);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_inode_notifysecctx)(struct inode *inode, void *ctx, u32 ctxlen)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_notifysecctx, inode, ctx, ctxlen);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_setsecctx)(struct dentry *dentry, void *ctx, u32 ctxlen)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_setsecctx, dentry, ctx, ctxlen);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_inode_getsecctx)(struct inode *inode, void **ctx, u32 *ctxlen)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inode_getsecctx, inode, ctx, ctxlen);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// CONFIG_WATCH_QUEUE
int lsm_replace(security_post_notification)(const struct cred *w_cred, const struct cred *cred,
                                            struct watch_notification *n)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_post_notification, w_cred, cred, n);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// CONFIG_KEY_NOTIFICATIONS
int lsm_replace(security_watch_key)(struct key *key)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_watch_key, key);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// CONFIG_SECURITY_NETWORK
int lsm_replace(security_unix_stream_connect)(struct sock *sock, struct sock *other, struct sock *newsk)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_unix_stream_connect, sock, other, newsk);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_unix_may_send)(struct socket *sock, struct socket *other)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_unix_may_send, sock, other);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_create)(int family, int type, int protocol, int kern)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_create, family, type, protocol, kern);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_post_create)(struct socket *sock, int family, int type, int protocol, int kern)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_post_create, sock, family, type, protocol, kern);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_socketpair)(struct socket *socka, struct socket *sockb)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_socketpair, socka, sockb);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_bind)(struct socket *sock, struct sockaddr *address, int addrlen)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_bind, sock, address, addrlen);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_connect)(struct socket *sock, struct sockaddr *address, int addrlen)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_connect, sock, address, addrlen);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_listen)(struct socket *sock, int backlog)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_listen, sock, backlog);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_accept)(struct socket *sock, struct socket *newsock)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_accept, sock, newsock);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_sendmsg)(struct socket *sock, struct msghdr *msg, int size)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_sendmsg, sock, msg, size);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_recvmsg)(struct socket *sock, struct msghdr *msg, int size, int flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_recvmsg, sock, msg, size, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_getsockname)(struct socket *sock)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_getsockname, sock);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_getpeername)(struct socket *sock)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_getpeername, sock);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_getsockopt)(struct socket *sock, int level, int optname)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_getsockopt, sock, level, optname);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_setsockopt)(struct socket *sock, int level, int optname)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_setsockopt, sock, level, optname);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_shutdown)(struct socket *sock, int how)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_shutdown, sock, how);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sock_rcv_skb)(struct sock *sk, struct sk_buff *skb)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sock_rcv_skb, sk, skb);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_getpeersec_stream)(struct socket *sock, sockptr_t optval, sockptr_t optlen,
                                                   unsigned int len)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_getpeersec_stream, sock, optval, optlen, len);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_socket_getpeersec_dgram)(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_socket_getpeersec_dgram, sock, skb, secid);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sk_alloc)(struct sock *sk, int family, gfp_t priority)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sk_alloc, sk, family, priority);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_sk_free)(struct sock *sk)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_sk_free, sk);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_sk_clone)(const struct sock *sk, struct sock *newsk)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_sk_clone, sk, newsk);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_sk_classify_flow)(struct sock *sk, struct flowi_common *flic)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_sk_classify_flow, sk, flic);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_req_classify_flow)(const struct request_sock *req, struct flowi_common *flic)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_req_classify_flow, req, flic);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_sock_graft)(struct sock *sk, struct socket *parent)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_sock_graft, sk, parent);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_inet_conn_request)(const struct sock *sk, struct sk_buff *skb, struct request_sock *req)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_inet_conn_request, sk, skb, req);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_inet_csk_clone)(struct sock *newsk, const struct request_sock *req)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_inet_csk_clone, newsk, req);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_inet_conn_established)(struct sock *sk, struct sk_buff *skb)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_inet_conn_established, sk, skb);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_secmark_relabel_packet)(u32 secid)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_secmark_relabel_packet, secid);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_secmark_refcount_inc)(void)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_secmark_refcount_inc, );
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_secmark_refcount_dec)(void)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_secmark_refcount_dec);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_tun_dev_alloc_security)(void **security)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_tun_dev_alloc_security, security);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_tun_dev_free_security)(void *security)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_tun_dev_free_security, security);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_tun_dev_create)(void)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_tun_dev_create);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_tun_dev_attach_queue)(void *security)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_tun_dev_attach_queue, security);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_tun_dev_attach)(struct sock *sk, void *security)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_tun_dev_attach, sk, security);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_tun_dev_open)(void *security)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_tun_dev_open, security);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sctp_assoc_request)(struct sctp_association *asoc, struct sk_buff *skb)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sctp_assoc_request, asoc, skb);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_sctp_bind_connect)(struct sock *sk, int optname, struct sockaddr *address, int addrlen)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sctp_bind_connect, sk, optname, address, addrlen);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_sctp_sk_clone)(struct sctp_association *asoc, struct sock *sk, struct sock *newsk)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_sctp_sk_clone, asoc, sk, newsk);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_sctp_assoc_established)(struct sctp_association *asoc, struct sk_buff *skb)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_sctp_assoc_established, asoc, skb);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// CONFIG_SECURITY_INFINIBAND
int lsm_replace(security_ib_pkey_access)(void *sec, u64 subnet_prefix, u16 pkey)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_ib_pkey_access, sec, subnet_prefix, pkey);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_ib_endport_manage_subnet)(void *sec, const char *dev_name, u8 port_num)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_ib_endport_manage_subnet, sec, dev_name, port_num);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_ib_alloc_security)(void **sec)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_ib_alloc_security, sec);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_ib_free_security)(void *sec)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_ib_free_security, sec);
    white_cred_after((void)0);
    lsm_void_hook_after;
}

// CONFIG_SECURITY_NETWORK_XFRM
int lsm_replace(security_xfrm_policy_alloc)(struct xfrm_sec_ctx **ctxp, struct xfrm_user_sec_ctx *sec_ctx, gfp_t gfp)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_xfrm_policy_alloc, ctxp, sec_ctx, gfp);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_xfrm_policy_clone)(struct xfrm_sec_ctx *old_ctx, struct xfrm_sec_ctx **new_ctxp)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_xfrm_policy_clone, old_ctx, new_ctxp);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_xfrm_policy_free)(struct xfrm_sec_ctx *ctx)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_xfrm_policy_free, ctx);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_xfrm_policy_delete)(struct xfrm_sec_ctx *ctx)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_xfrm_policy_delete, ctx);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_xfrm_state_alloc)(struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_xfrm_state_alloc, x, sec_ctx);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_xfrm_state_alloc_acquire)(struct xfrm_state *x, struct xfrm_sec_ctx *polsec, u32 secid)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_xfrm_state_alloc_acquire, x, polsec, secid);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_xfrm_state_delete)(struct xfrm_state *x)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_xfrm_state_delete, x);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_xfrm_state_free)(struct xfrm_state *x)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_xfrm_state_free, x);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_xfrm_policy_lookup)(struct xfrm_sec_ctx *ctx, u32 fl_secid)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_xfrm_policy_lookup, ctx, fl_secid);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_xfrm_state_pol_flow_match)(struct xfrm_state *x, struct xfrm_policy *xp,
                                                    const struct flowi_common *flic)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_xfrm_state_pol_flow_match, x, xp, flic);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_xfrm_decode_session)(struct sk_buff *skb, u32 *secid)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_xfrm_decode_session, skb, secid);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_skb_classify_flow)(struct sk_buff *skb, struct flowi_common *flic)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_skb_classify_flow, skb, flic);
    white_cred_after((void)0);
    lsm_void_hook_after;
}

/* key management security hooks */
// CONFIG_KEYS
int lsm_replace(security_key_alloc)(struct key *key, const struct cred *cred, unsigned long flags)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_key_alloc, key, cred, flags);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_key_free)(struct key *key)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_key_free, key);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_key_permission)(key_ref_t key_ref, const struct cred *cred, enum key_need_perm need_perm)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_key_permission, key_ref, cred, need_perm);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_key_getsecurity)(struct key *key, char **_buffer)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_key_getsecurity, key, _buffer);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// CONFIG_AUDIT
int lsm_replace(security_audit_rule_init)(u32 field, u32 op, char *rulestr, void **lsmrule)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_audit_rule_init, field, op, rulestr, lsmrule);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_audit_rule_known)(struct audit_krule *krule)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_audit_rule_known, krule);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_audit_rule_free)(void *lsmrule)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_audit_rule_free, lsmrule);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_audit_rule_match)(u32 secid, u32 field, u32 op, void *lsmrule)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_audit_rule_match, secid, field, op, lsmrule);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// CONFIG_BPF_SYSCALL
int lsm_replace(security_bpf)(int cmd, union bpf_attr *attr, unsigned int size)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_bpf, cmd, attr, size);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_bpf_map)(struct bpf_map *map, fmode_t fmode)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_bpf_map, map, fmode);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_bpf_prog)(struct bpf_prog *prog)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_bpf_prog, prog);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_bpf_map_alloc)(struct bpf_map *map)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_bpf_map_alloc, map);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_bpf_prog_alloc)(struct bpf_prog_aux *aux)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_bpf_prog_alloc, aux);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_bpf_map_free)(struct bpf_map *map)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_bpf_map_free, map);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
void lsm_replace(security_bpf_prog_free)(struct bpf_prog_aux *aux)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_bpf_prog_free, aux);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
// CONFIG_BPF_SYSCALL

int lsm_replace(security_locked_down)(enum lockdown_reason what)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_locked_down, what);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// CONFIG_PERF_EVENTS
int lsm_replace(security_perf_event_open)(struct perf_event_attr *attr, int type)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_perf_event_open, attr, type);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_perf_event_alloc)(struct perf_event *event)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_perf_event_alloc, event);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
void lsm_replace(security_perf_event_free)(struct perf_event *event)
{
    lsm_void_hook_before;
    white_cred_before((void)0);
    lsm_call_backup(security_perf_event_free, event);
    white_cred_after((void)0);
    lsm_void_hook_after;
}
int lsm_replace(security_perf_event_read)(struct perf_event *event)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_perf_event_read, event);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_perf_event_write)(struct perf_event *event)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_perf_event_write, event);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

// CONFIG_IO_URING
int lsm_replace(security_uring_override_creds)(const struct cred *new)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_uring_override_creds, new);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_uring_sqpoll)(void)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_uring_sqpoll);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}
int lsm_replace(security_uring_cmd)(struct io_uring_cmd *ioucmd)
{
    lsm_int_hook_before;
    white_cred_before(0);
    int ret = lsm_call_backup(security_uring_cmd, ioucmd);
    white_cred_after(0);
    lsm_int_hook_after;
    return ret;
}

int lsm_hook_install()
{
    // Security hooks for program execution operations.
    lsm_hook(security_binder_set_context_mgr);
    lsm_hook(security_binder_transaction);
    lsm_hook(security_binder_transfer_binder);
    lsm_hook(security_binder_transfer_file);
    lsm_hook(security_ptrace_access_check);
    lsm_hook(security_ptrace_traceme);
    lsm_hook(security_capget);
    lsm_hook(security_capset);
    lsm_hook(security_capable);
    lsm_hook(security_quotactl);
    lsm_hook(security_quota_on);
    lsm_hook(security_syslog);
    lsm_hook(security_settime64);
    lsm_hook(security_vm_enough_memory_mm);
    lsm_hook(security_bprm_creds_for_exec);
    lsm_hook(security_bprm_creds_from_file);
    lsm_hook(security_bprm_check);
    lsm_hook(security_bprm_committing_creds);
    lsm_hook(security_bprm_committed_creds);

    // Security hooks for mount using fs_context.
    lsm_hook(security_fs_context_dup);
    lsm_hook(security_fs_context_parse_param);

    // Security hooks for filesystem operations.
    lsm_hook(security_sb_alloc);
    lsm_hook(security_sb_delete);
    lsm_hook(security_sb_free);
    lsm_hook(security_free_mnt_opts);
    lsm_hook(security_sb_eat_lsm_opts);
    lsm_hook(security_sb_remount);
    lsm_hook(security_sb_kern_mount);
    lsm_hook(security_sb_show_options);
    lsm_hook(security_sb_statfs);
    lsm_hook(security_sb_mount);
    lsm_hook(security_sb_umount);
    lsm_hook(security_sb_pivotroot);
    lsm_hook(security_sb_set_mnt_opts);
    lsm_hook(security_sb_clone_mnt_opts);
    lsm_hook(security_add_mnt_opt);
    lsm_hook(security_move_mount);
    lsm_hook(security_dentry_init_security);
    lsm_hook(security_dentry_create_files_as);

    // //CONFIG_SECURITY_PATH
    lsm_hook(security_path_unlink);
    lsm_hook(security_path_mkdir);
    lsm_hook(security_path_rmdir);
    lsm_hook(security_path_mknod);
    lsm_hook(security_path_truncate);
    lsm_hook(security_path_symlink);
    lsm_hook(security_path_link);
    lsm_hook(security_path_rename);
    lsm_hook(security_path_chmod);
    lsm_hook(security_path_chown);
    lsm_hook(security_path_chroot);
    /* CONFIG_SECURITY_PATH */

    /* Needed for inode based security check */
    lsm_hook(security_path_notify);
    lsm_hook(security_inode_alloc);
    lsm_hook(security_inode_free);
    lsm_hook(security_inode_init_security);
    lsm_hook(security_old_inode_init_security);
    lsm_hook(security_inode_create);
    lsm_hook(security_inode_link);
    lsm_hook(security_inode_unlink);
    lsm_hook(security_inode_symlink);
    lsm_hook(security_inode_mkdir);
    lsm_hook(security_inode_rmdir);
    lsm_hook(security_inode_mknod);
    lsm_hook(security_inode_rename);
    lsm_hook(security_inode_readlink);
    lsm_hook(security_inode_follow_link);
    lsm_hook(security_inode_permission);
    lsm_hook(security_inode_setattr);
    lsm_hook(security_inode_getattr);
    lsm_hook(security_inode_setxattr);
    lsm_hook(security_inode_post_setxattr);
    lsm_hook(security_inode_getxattr);
    lsm_hook(security_inode_listxattr);
    lsm_hook(security_inode_removexattr);
    lsm_hook(security_inode_set_acl);
    lsm_hook(security_inode_get_acl);
    lsm_hook(security_inode_remove_acl);
    lsm_hook(security_inode_need_killpriv);
    lsm_hook(security_inode_killpriv);
    lsm_hook(security_inode_getsecurity);
    lsm_hook(security_inode_setsecurity);
    lsm_hook(security_inode_listsecurity);
    lsm_hook(security_inode_getsecid);
    lsm_hook(security_inode_copy_up);
    lsm_hook(security_inode_copy_up_xattr);
    lsm_hook(security_kernfs_init_security);
    lsm_hook(security_file_permission);
    lsm_hook(security_file_alloc);
    lsm_hook(security_file_free);
    lsm_hook(security_file_ioctl);
    lsm_hook(security_mmap_addr);
    lsm_hook(security_mmap_file);
    lsm_hook(security_file_mprotect);
    lsm_hook(security_file_lock);
    lsm_hook(security_file_fcntl);
    lsm_hook(security_file_set_fowner);
    lsm_hook(security_file_send_sigiotask);
    lsm_hook(security_file_receive);
    lsm_hook(security_file_open);
    lsm_hook(security_file_truncate);
    lsm_hook(security_task_alloc);
    lsm_hook(security_task_free);
    lsm_hook(security_cred_alloc_blank);
    lsm_hook(security_cred_free);
    lsm_hook(security_prepare_creds);
    lsm_hook(security_transfer_creds);
    lsm_hook(security_cred_getsecid);
    lsm_hook(security_kernel_act_as);
    lsm_hook(security_kernel_create_files_as);
    lsm_hook(security_kernel_module_request);
    lsm_hook(security_kernel_load_data);
    lsm_hook(security_kernel_post_load_data);
    lsm_hook(security_kernel_read_file);
    lsm_hook(security_kernel_post_read_file);
    lsm_hook(security_task_fix_setuid);
    lsm_hook(security_task_fix_setgid);
    lsm_hook(security_task_fix_setgroups);
    lsm_hook(security_task_setpgid);
    lsm_hook(security_task_getpgid);
    lsm_hook(security_task_getsid);
    lsm_hook(security_current_getsecid_subj);
    lsm_hook(security_task_getsecid_obj);
    lsm_hook(security_task_getsecid);
    lsm_hook(security_task_setnice);
    lsm_hook(security_task_setioprio);
    lsm_hook(security_task_getioprio);
    lsm_hook(security_task_prlimit);
    lsm_hook(security_task_setrlimit);
    lsm_hook(security_task_setscheduler);
    lsm_hook(security_task_getscheduler);
    lsm_hook(security_task_movememory);
    lsm_hook(security_task_kill);
    lsm_hook(security_task_prctl);
    lsm_hook(security_task_to_inode);
    lsm_hook(security_create_user_ns);
    lsm_hook(security_ipc_permission);
    lsm_hook(security_ipc_getsecid);
    lsm_hook(security_msg_msg_alloc);
    lsm_hook(security_msg_msg_free);
    lsm_hook(security_msg_queue_alloc);
    lsm_hook(security_msg_queue_free);
    lsm_hook(security_msg_queue_associate);
    lsm_hook(security_msg_queue_msgctl);
    lsm_hook(security_msg_queue_msgsnd);
    lsm_hook(security_msg_queue_msgrcv);
    lsm_hook(security_shm_alloc);
    lsm_hook(security_shm_free);
    lsm_hook(security_shm_associate);
    lsm_hook(security_shm_shmctl);
    lsm_hook(security_shm_shmat);
    lsm_hook(security_sem_alloc);
    lsm_hook(security_sem_free);
    lsm_hook(security_sem_associate);
    lsm_hook(security_sem_semctl);
    lsm_hook(security_sem_semop);
    lsm_hook(security_d_instantiate);
    lsm_hook(security_getprocattr);
    lsm_hook(security_setprocattr);
    lsm_hook(security_netlink_send);
    lsm_hook(security_ismaclabel);
    lsm_hook(security_secid_to_secctx);
    lsm_hook(security_secctx_to_secid);
    lsm_hook(security_release_secctx);
    lsm_hook(security_inode_invalidate_secctx);
    lsm_hook(security_inode_notifysecctx);
    lsm_hook(security_inode_setsecctx);
    lsm_hook(security_inode_getsecctx);

    // CONFIG_WATCH_QUEUE
    lsm_hook(security_post_notification);

    // CONFIG_KEY_NOTIFICATIONS
    lsm_hook(security_watch_key);

    // CONFIG_SECURITY_NETWORK
    lsm_hook(security_unix_stream_connect);
    lsm_hook(security_unix_may_send);
    lsm_hook(security_socket_create);
    lsm_hook(security_socket_post_create);
    lsm_hook(security_socket_socketpair);
    lsm_hook(security_socket_bind);
    lsm_hook(security_socket_connect);
    lsm_hook(security_socket_listen);
    lsm_hook(security_socket_accept);
    lsm_hook(security_socket_sendmsg);
    lsm_hook(security_socket_recvmsg);
    lsm_hook(security_socket_getsockname);
    lsm_hook(security_socket_getpeername);
    lsm_hook(security_socket_getsockopt);
    lsm_hook(security_socket_setsockopt);
    lsm_hook(security_socket_shutdown);
    lsm_hook(security_sock_rcv_skb);
    lsm_hook(security_socket_getpeersec_stream);
    lsm_hook(security_socket_getpeersec_dgram);
    lsm_hook(security_sk_alloc);
    lsm_hook(security_sk_free);
    lsm_hook(security_sk_clone);
    lsm_hook(security_sk_classify_flow);
    lsm_hook(security_req_classify_flow);
    lsm_hook(security_sock_graft);
    lsm_hook(security_inet_conn_request);
    lsm_hook(security_inet_csk_clone);
    lsm_hook(security_inet_conn_established);
    lsm_hook(security_secmark_relabel_packet);
    lsm_hook(security_secmark_refcount_inc);
    lsm_hook(security_secmark_refcount_dec);
    lsm_hook(security_tun_dev_alloc_security);
    lsm_hook(security_tun_dev_free_security);
    lsm_hook(security_tun_dev_create);
    lsm_hook(security_tun_dev_attach_queue);
    lsm_hook(security_tun_dev_attach);
    lsm_hook(security_tun_dev_open);
    lsm_hook(security_sctp_assoc_request);
    lsm_hook(security_sctp_bind_connect);
    lsm_hook(security_sctp_sk_clone);
    lsm_hook(security_sctp_assoc_established);

    // CONFIG_SECURITY_INFINIBAND
    lsm_hook(security_ib_pkey_access);
    lsm_hook(security_ib_endport_manage_subnet);
    lsm_hook(security_ib_alloc_security);
    lsm_hook(security_ib_free_security);

    // CONFIG_SECURITY_NETWORK_XFRM
    lsm_hook(security_xfrm_policy_alloc);
    lsm_hook(security_xfrm_policy_clone);
    lsm_hook(security_xfrm_policy_free);
    lsm_hook(security_xfrm_policy_delete);
    lsm_hook(security_xfrm_state_alloc);
    lsm_hook(security_xfrm_state_alloc_acquire);
    lsm_hook(security_xfrm_state_delete);
    lsm_hook(security_xfrm_state_free);
    lsm_hook(security_xfrm_policy_lookup);
    lsm_hook(security_xfrm_state_pol_flow_match);
    lsm_hook(security_xfrm_decode_session);
    lsm_hook(security_skb_classify_flow);

    /* key management security hooks */
    // CONFIG_KEYS
    lsm_hook(security_key_alloc);
    lsm_hook(security_key_free);
    lsm_hook(security_key_permission);
    lsm_hook(security_key_getsecurity);

    // CONFIG_AUDIT
    lsm_hook(security_audit_rule_init);
    lsm_hook(security_audit_rule_known);
    lsm_hook(security_audit_rule_free);
    lsm_hook(security_audit_rule_match);

    // CONFIG_BPF_SYSCALL
    lsm_hook(security_bpf);
    lsm_hook(security_bpf_map);
    lsm_hook(security_bpf_prog);
    lsm_hook(security_bpf_map_alloc);
    lsm_hook(security_bpf_prog_alloc);
    lsm_hook(security_bpf_map_free);
    lsm_hook(security_bpf_prog_free);
    // CONFIG_BPF_SYSCALL

    lsm_hook(security_locked_down);

    // CONFIG_PERF_EVENTS
    lsm_hook(security_perf_event_open);
    lsm_hook(security_perf_event_alloc);
    lsm_hook(security_perf_event_free);
    lsm_hook(security_perf_event_read);
    lsm_hook(security_perf_event_write);

    // CONFIG_IO_URING
    lsm_hook(security_uring_override_creds);
    lsm_hook(security_uring_sqpoll);
    lsm_hook(security_uring_cmd);

    return 0;
}
