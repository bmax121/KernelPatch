#include <linux/security.h>

//
/* Security operations */
int kfunc_def(security_binder_set_context_mgr)(const struct cred *mgr) = 0;
int kfunc_def(security_binder_transaction)(const struct cred *from, const struct cred *to) = 0;
int kfunc_def(security_binder_transfer_binder)(const struct cred *from, const struct cred *to) = 0;
int kfunc_def(security_binder_transfer_file)(const struct cred *from, const struct cred *to, struct file *file) = 0;
int kfunc_def(security_ptrace_access_check)(struct task_struct *child, unsigned int mode) = 0;
int kfunc_def(security_ptrace_traceme)(struct task_struct *parent) = 0;
int kfunc_def(security_capget)(struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable,
                               kernel_cap_t *permitted) = 0;
int kfunc_def(security_capset)(struct cred *new, const struct cred *old, const kernel_cap_t *effective,
                               const kernel_cap_t *inheritable, const kernel_cap_t *permitted) = 0;
int kfunc_def(security_capable)(const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts) = 0;
int kfunc_def(security_quotactl)(int cmds, int type, int id, struct super_block *sb) = 0;
int kfunc_def(security_quota_on)(struct dentry *dentry) = 0;
int kfunc_def(security_syslog)(int type) = 0;
int kfunc_def(security_settime64)(const struct timespec64 *ts, const struct timezone *tz) = 0;
int kfunc_def(security_vm_enough_memory_mm)(struct mm_struct *mm, long pages) = 0;
int kfunc_def(security_bprm_creds_for_exec)(struct linux_binprm *bprm) = 0;
int kfunc_def(security_bprm_creds_from_file)(struct linux_binprm *bprm, struct file *file) = 0;
int kfunc_def(security_bprm_check)(struct linux_binprm *bprm) = 0;
void kfunc_def(security_bprm_committing_creds)(struct linux_binprm *bprm) = 0;
void kfunc_def(security_bprm_committed_creds)(struct linux_binprm *bprm) = 0;
int kfunc_def(security_fs_context_dup)(struct fs_context *fc, struct fs_context *src_fc) = 0;
int kfunc_def(security_fs_context_parse_param)(struct fs_context *fc, struct fs_parameter *param) = 0;
int kfunc_def(security_sb_alloc)(struct super_block *sb) = 0;
void kfunc_def(security_sb_delete)(struct super_block *sb) = 0;
void kfunc_def(security_sb_free)(struct super_block *sb) = 0;
void kfunc_def(security_free_mnt_opts)(void **mnt_opts) = 0;
int kfunc_def(security_sb_eat_lsm_opts)(char *options, void **mnt_opts) = 0;
int kfunc_def(security_sb_remount)(struct super_block *sb, void *mnt_opts) = 0;
int kfunc_def(security_sb_kern_mount)(struct super_block *sb) = 0;
int kfunc_def(security_sb_show_options)(struct seq_file *m, struct super_block *sb) = 0;
int kfunc_def(security_sb_statfs)(struct dentry *dentry) = 0;
int kfunc_def(security_sb_mount)(const char *dev_name, const struct path *path, const char *type, unsigned long flags,
                                 void *data) = 0;
int kfunc_def(security_sb_umount)(struct vfsmount *mnt, int flags) = 0;
int kfunc_def(security_sb_pivotroot)(const struct path *old_path, const struct path *new_path) = 0;
int kfunc_def(security_sb_set_mnt_opts)(struct super_block *sb, void *mnt_opts, unsigned long kern_flags,
                                        unsigned long *set_kern_flags) = 0;
int kfunc_def(security_sb_clone_mnt_opts)(const struct super_block *oldsb, struct super_block *newsb,
                                          unsigned long kern_flags, unsigned long *set_kern_flags) = 0;
int kfunc_def(security_add_mnt_opt)(const char *option, const char *val, int len, void **mnt_opts) = 0;
int kfunc_def(security_move_mount)(const struct path *from_path, const struct path *to_path) = 0;
int kfunc_def(security_dentry_init_security)(struct dentry *dentry, int mode, const struct qstr *name, void **ctx,
                                             u32 *ctxlen) = 0;
int kfunc_def(security_dentry_create_files_as)(struct dentry *dentry, int mode, struct qstr *name,
                                               const struct cred *old, struct cred *new) = 0;

//CONFIG_SECURITY_PATH
int kfunc_def(security_path_unlink)(const struct path *dir, struct dentry *dentry) = 0;
int kfunc_def(security_path_mkdir)(const struct path *dir, struct dentry *dentry, umode_t mode) = 0;
int kfunc_def(security_path_rmdir)(const struct path *dir, struct dentry *dentry) = 0;
int kfunc_def(security_path_mknod)(const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev) = 0;
int kfunc_def(security_path_truncate)(const struct path *path) = 0;
int kfunc_def(security_path_symlink)(const struct path *dir, struct dentry *dentry, const char *old_name) = 0;
int kfunc_def(security_path_link)(struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry) = 0;
int kfunc_def(security_path_rename)(const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir,
                                    struct dentry *new_dentry, unsigned int flags) = 0;
int kfunc_def(security_path_chmod)(const struct path *path, umode_t mode) = 0;
int kfunc_def(security_path_chown)(const struct path *path, kuid_t uid, kgid_t gid) = 0;
int kfunc_def(security_path_chroot)(const struct path *path) = 0;
/* CONFIG_SECURITY_PATH */

/* Needed for inode based security check */
int kfunc_def(security_path_notify)(const struct path *path, u64 mask, unsigned int obj_type) = 0;
int kfunc_def(security_inode_alloc)(struct inode *inode) = 0;
void kfunc_def(security_inode_free)(struct inode *inode) = 0;
int kfunc_def(security_inode_init_security)(struct inode *inode, struct inode *dir, const struct qstr *qstr,
                                            initxattrs initxattrs, void *fs_data) = 0;
int kfunc_def(security_old_inode_init_security)(struct inode *inode, struct inode *dir, const struct qstr *qstr,
                                                const char **name, void **value, size_t *len) = 0;
int kfunc_def(security_inode_create)(struct inode *dir, struct dentry *dentry, umode_t mode) = 0;
int kfunc_def(security_inode_link)(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) = 0;
int kfunc_def(security_inode_unlink)(struct inode *dir, struct dentry *dentry) = 0;
int kfunc_def(security_inode_symlink)(struct inode *dir, struct dentry *dentry, const char *old_name) = 0;
int kfunc_def(security_inode_mkdir)(struct inode *dir, struct dentry *dentry, umode_t mode) = 0;
int kfunc_def(security_inode_rmdir)(struct inode *dir, struct dentry *dentry) = 0;
int kfunc_def(security_inode_mknod)(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev) = 0;
int kfunc_def(security_inode_rename)(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
                                     struct dentry *new_dentry, unsigned int flags) = 0;
int kfunc_def(security_inode_readlink)(struct dentry *dentry) = 0;
int kfunc_def(security_inode_follow_link)(struct dentry *dentry, struct inode *inode, bool rcu) = 0;
int kfunc_def(security_inode_permission)(struct inode *inode, int mask) = 0;
int kfunc_def(security_inode_setattr)(struct dentry *dentry, struct iattr *attr) = 0;
int kfunc_def(security_inode_getattr)(const struct path *path) = 0;
int kfunc_def(security_inode_setxattr)(struct dentry *dentry, const char *name, const void *value, size_t size,
                                       int flags) = 0;
void kfunc_def(security_inode_post_setxattr)(struct dentry *dentry, const char *name, const void *value, size_t size,
                                             int flags) = 0;
int kfunc_def(security_inode_getxattr)(struct dentry *dentry, const char *name) = 0;
int kfunc_def(security_inode_listxattr)(struct dentry *dentry) = 0;
int kfunc_def(security_inode_removexattr)(struct dentry *dentry, const char *name) = 0;
int kfunc_def(security_inode_set_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name,
                                      struct posix_acl *kacl) = 0;
int kfunc_def(security_inode_get_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name) = 0;
int kfunc_def(security_inode_remove_acl)(struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name) = 0;
int kfunc_def(security_inode_need_killpriv)(struct dentry *dentry) = 0;
int kfunc_def(security_inode_killpriv)(struct dentry *dentry) = 0;
int kfunc_def(security_inode_getsecurity)(struct inode *inode, const char *name, void **buffer, bool alloc) = 0;
int kfunc_def(security_inode_setsecurity)(struct inode *inode, const char *name, const void *value, size_t size,
                                          int flags) = 0;
int kfunc_def(security_inode_listsecurity)(struct inode *inode, char *buffer, size_t buffer_size) = 0;
void kfunc_def(security_inode_getsecid)(struct inode *inode, u32 *secid) = 0;
int kfunc_def(security_inode_copy_up)(struct dentry *src, struct cred **new) = 0;
int kfunc_def(security_inode_copy_up_xattr)(const char *name) = 0;
int kfunc_def(security_kernfs_init_security)(struct kernfs_node *kn_dir, struct kernfs_node *kn) = 0;
int kfunc_def(security_file_permission)(struct file *file, int mask) = 0;
int kfunc_def(security_file_alloc)(struct file *file) = 0;
void kfunc_def(security_file_free)(struct file *file) = 0;
int kfunc_def(security_file_ioctl)(struct file *file, unsigned int cmd, unsigned long arg) = 0;
int kfunc_def(security_mmap_addr)(unsigned long addr) = 0;
int kfunc_def(security_mmap_file)(struct file *file, unsigned long prot, unsigned long flags) = 0;
int kfunc_def(security_file_mprotect)(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot) = 0;
int kfunc_def(security_file_lock)(struct file *file, unsigned int cmd) = 0;
int kfunc_def(security_file_fcntl)(struct file *file, unsigned int cmd, unsigned long arg) = 0;
void kfunc_def(security_file_set_fowner)(struct file *file) = 0;
int kfunc_def(security_file_send_sigiotask)(struct task_struct *tsk, struct fown_struct *fown, int sig) = 0;
int kfunc_def(security_file_receive)(struct file *file) = 0;
// int kfunc_def(security_file_open)(struct file *file) = 0;
int kfunc_def(security_file_open)(struct file *file, const struct cred *cred) = 0;
int kfunc_def(security_file_truncate)(struct file *file) = 0;
int kfunc_def(security_task_alloc)(struct task_struct *task, unsigned long clone_flags) = 0;
void kfunc_def(security_task_free)(struct task_struct *task) = 0;
int kfunc_def(security_cred_alloc_blank)(struct cred *cred, gfp_t gfp) = 0;
void kfunc_def(security_cred_free)(struct cred *cred) = 0;
int kfunc_def(security_prepare_creds)(struct cred *new, const struct cred *old, gfp_t gfp) = 0;
void kfunc_def(security_transfer_creds)(struct cred *new, const struct cred *old) = 0;
void kfunc_def(security_cred_getsecid)(const struct cred *c, u32 *secid) = 0;
int kfunc_def(security_kernel_act_as)(struct cred *new, u32 secid) = 0;
int kfunc_def(security_kernel_create_files_as)(struct cred *new, struct inode *inode) = 0;
int kfunc_def(security_kernel_module_request)(char *kmod_name) = 0;
int kfunc_def(security_kernel_load_data)(enum kernel_load_data_id id, bool contents) = 0;
int kfunc_def(security_kernel_post_load_data)(char *buf, loff_t size, enum kernel_load_data_id id,
                                              char *description) = 0;
int kfunc_def(security_kernel_read_file)(struct file *file, enum kernel_read_file_id id, bool contents) = 0;
int kfunc_def(security_kernel_post_read_file)(struct file *file, char *buf, loff_t size,
                                              enum kernel_read_file_id id) = 0;
int kfunc_def(security_task_fix_setuid)(struct cred *new, const struct cred *old, int flags) = 0;
int kfunc_def(security_task_fix_setgid)(struct cred *new, const struct cred *old, int flags) = 0;
int kfunc_def(security_task_fix_setgroups)(struct cred *new, const struct cred *old) = 0;
int kfunc_def(security_task_setpgid)(struct task_struct *p, pid_t pgid) = 0;
int kfunc_def(security_task_getpgid)(struct task_struct *p) = 0;
int kfunc_def(security_task_getsid)(struct task_struct *p) = 0;

void kfunc_def(security_current_getsecid_subj)(u32 *secid); // 5.10
void kfunc_def(security_task_getsecid_obj)(struct task_struct *p, u32 *secid); // ?-6.3
void kfunc_def(security_task_getsecid)(struct task_struct *p, u32 *secid); // 4.4-5.10

int kfunc_def(security_task_setnice)(struct task_struct *p, int nice) = 0;
int kfunc_def(security_task_setioprio)(struct task_struct *p, int ioprio) = 0;
int kfunc_def(security_task_getioprio)(struct task_struct *p) = 0;
int kfunc_def(security_task_prlimit)(const struct cred *cred, const struct cred *tcred, unsigned int flags) = 0;
int kfunc_def(security_task_setrlimit)(struct task_struct *p, unsigned int resource, struct rlimit *new_rlim) = 0;
int kfunc_def(security_task_setscheduler)(struct task_struct *p) = 0;
int kfunc_def(security_task_getscheduler)(struct task_struct *p) = 0;
int kfunc_def(security_task_movememory)(struct task_struct *p) = 0;
int kfunc_def(security_task_kill)(struct task_struct *p, struct kernel_siginfo *info, int sig,
                                  const struct cred *cred) = 0;
int kfunc_def(security_task_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
                                   unsigned long arg5) = 0;
void kfunc_def(security_task_to_inode)(struct task_struct *p, struct inode *inode) = 0;
int kfunc_def(security_create_user_ns)(const struct cred *cred) = 0;
int kfunc_def(security_ipc_permission)(struct kern_ipc_perm *ipcp, short flag) = 0;
void kfunc_def(security_ipc_getsecid)(struct kern_ipc_perm *ipcp, u32 *secid) = 0;
int kfunc_def(security_msg_msg_alloc)(struct msg_msg *msg) = 0;
void kfunc_def(security_msg_msg_free)(struct msg_msg *msg) = 0;
int kfunc_def(security_msg_queue_alloc)(struct kern_ipc_perm *msq) = 0;
void kfunc_def(security_msg_queue_free)(struct kern_ipc_perm *msq) = 0;
int kfunc_def(security_msg_queue_associate)(struct kern_ipc_perm *msq, int msqflg) = 0;
int kfunc_def(security_msg_queue_msgctl)(struct kern_ipc_perm *msq, int cmd) = 0;
int kfunc_def(security_msg_queue_msgsnd)(struct kern_ipc_perm *msq, struct msg_msg *msg, int msqflg) = 0;
int kfunc_def(security_msg_queue_msgrcv)(struct kern_ipc_perm *msq, struct msg_msg *msg, struct task_struct *target,
                                         long type, int mode) = 0;
int kfunc_def(security_shm_alloc)(struct kern_ipc_perm *shp) = 0;
void kfunc_def(security_shm_free)(struct kern_ipc_perm *shp) = 0;
int kfunc_def(security_shm_associate)(struct kern_ipc_perm *shp, int shmflg) = 0;
int kfunc_def(security_shm_shmctl)(struct kern_ipc_perm *shp, int cmd) = 0;
int kfunc_def(security_shm_shmat)(struct kern_ipc_perm *shp, char __user *shmaddr, int shmflg) = 0;
int kfunc_def(security_sem_alloc)(struct kern_ipc_perm *sma) = 0;
void kfunc_def(security_sem_free)(struct kern_ipc_perm *sma) = 0;
int kfunc_def(security_sem_associate)(struct kern_ipc_perm *sma, int semflg) = 0;
int kfunc_def(security_sem_semctl)(struct kern_ipc_perm *sma, int cmd) = 0;
int kfunc_def(security_sem_semop)(struct kern_ipc_perm *sma, struct sembuf *sops, unsigned nsops, int alter) = 0;
void kfunc_def(security_d_instantiate)(struct dentry *dentry, struct inode *inode) = 0;
int kfunc_def(security_getprocattr)(struct task_struct *p, const char *lsm, char *name, char **value) = 0;
int kfunc_def(security_setprocattr)(const char *lsm, const char *name, void *value, size_t size) = 0;
int kfunc_def(security_netlink_send)(struct sock *sk, struct sk_buff *skb) = 0;
int kfunc_def(security_ismaclabel)(const char *name) = 0;
int kfunc_def(security_secid_to_secctx)(u32 secid, char **secdata, u32 *seclen) = 0;
int kfunc_def(security_secctx_to_secid)(const char *secdata, u32 seclen, u32 *secid) = 0;
void kfunc_def(security_release_secctx)(char *secdata, u32 seclen) = 0;
void kfunc_def(security_inode_invalidate_secctx)(struct inode *inode) = 0;
int kfunc_def(security_inode_notifysecctx)(struct inode *inode, void *ctx, u32 ctxlen) = 0;
int kfunc_def(security_inode_setsecctx)(struct dentry *dentry, void *ctx, u32 ctxlen) = 0;
int kfunc_def(security_inode_getsecctx)(struct inode *inode, void **ctx, u32 *ctxlen) = 0;

// CONFIG_WATCH_QUEUE
int kfunc_def(security_post_notification)(const struct cred *w_cred, const struct cred *cred,
                                          struct watch_notification *n) = 0;

// CONFIG_KEY_NOTIFICATIONS
int kfunc_def(security_watch_key)(struct key *key) = 0;

// CONFIG_SECURITY_NETWORK
int kfunc_def(security_unix_stream_connect)(struct sock *sock, struct sock *other, struct sock *newsk) = 0;
int kfunc_def(security_unix_may_send)(struct socket *sock, struct socket *other) = 0;
int kfunc_def(security_socket_create)(int family, int type, int protocol, int kern) = 0;
int kfunc_def(security_socket_post_create)(struct socket *sock, int family, int type, int protocol, int kern) = 0;
int kfunc_def(security_socket_socketpair)(struct socket *socka, struct socket *sockb) = 0;
int kfunc_def(security_socket_bind)(struct socket *sock, struct sockaddr *address, int addrlen) = 0;
int kfunc_def(security_socket_connect)(struct socket *sock, struct sockaddr *address, int addrlen) = 0;
int kfunc_def(security_socket_listen)(struct socket *sock, int backlog) = 0;
int kfunc_def(security_socket_accept)(struct socket *sock, struct socket *newsock) = 0;
int kfunc_def(security_socket_sendmsg)(struct socket *sock, struct msghdr *msg, int size) = 0;
int kfunc_def(security_socket_recvmsg)(struct socket *sock, struct msghdr *msg, int size, int flags) = 0;
int kfunc_def(security_socket_getsockname)(struct socket *sock) = 0;
int kfunc_def(security_socket_getpeername)(struct socket *sock) = 0;
int kfunc_def(security_socket_getsockopt)(struct socket *sock, int level, int optname) = 0;
int kfunc_def(security_socket_setsockopt)(struct socket *sock, int level, int optname) = 0;
int kfunc_def(security_socket_shutdown)(struct socket *sock, int how) = 0;
int kfunc_def(security_sock_rcv_skb)(struct sock *sk, struct sk_buff *skb) = 0;
int kfunc_def(security_socket_getpeersec_stream)(struct socket *sock, sockptr_t optval, sockptr_t optlen,
                                                 unsigned int len) = 0;
int kfunc_def(security_socket_getpeersec_dgram)(struct socket *sock, struct sk_buff *skb, u32 *secid) = 0;
int kfunc_def(security_sk_alloc)(struct sock *sk, int family, gfp_t priority) = 0;
void kfunc_def(security_sk_free)(struct sock *sk) = 0;
void kfunc_def(security_sk_clone)(const struct sock *sk, struct sock *newsk) = 0;
void kfunc_def(security_sk_classify_flow)(struct sock *sk, struct flowi_common *flic) = 0;
void kfunc_def(security_req_classify_flow)(const struct request_sock *req, struct flowi_common *flic) = 0;
void kfunc_def(security_sock_graft)(struct sock *sk, struct socket *parent) = 0;
int kfunc_def(security_inet_conn_request)(const struct sock *sk, struct sk_buff *skb, struct request_sock *req) = 0;
void kfunc_def(security_inet_csk_clone)(struct sock *newsk, const struct request_sock *req) = 0;
void kfunc_def(security_inet_conn_established)(struct sock *sk, struct sk_buff *skb) = 0;
int kfunc_def(security_secmark_relabel_packet)(u32 secid) = 0;
void kfunc_def(security_secmark_refcount_inc)(void) = 0;
void kfunc_def(security_secmark_refcount_dec)(void) = 0;
int kfunc_def(security_tun_dev_alloc_security)(void **security) = 0;
void kfunc_def(security_tun_dev_free_security)(void *security) = 0;
int kfunc_def(security_tun_dev_create)(void) = 0;
int kfunc_def(security_tun_dev_attach_queue)(void *security) = 0;
int kfunc_def(security_tun_dev_attach)(struct sock *sk, void *security) = 0;
int kfunc_def(security_tun_dev_open)(void *security) = 0;
int kfunc_def(security_sctp_assoc_request)(struct sctp_association *asoc, struct sk_buff *skb) = 0;
int kfunc_def(security_sctp_bind_connect)(struct sock *sk, int optname, struct sockaddr *address, int addrlen) = 0;
void kfunc_def(security_sctp_sk_clone)(struct sctp_association *asoc, struct sock *sk, struct sock *newsk) = 0;
int kfunc_def(security_sctp_assoc_established)(struct sctp_association *asoc, struct sk_buff *skb) = 0;

// CONFIG_SECURITY_INFINIBAND
int kfunc_def(security_ib_pkey_access)(void *sec, u64 subnet_prefix, u16 pkey) = 0;
int kfunc_def(security_ib_endport_manage_subnet)(void *sec, const char *dev_name, u8 port_num) = 0;
int kfunc_def(security_ib_alloc_security)(void **sec) = 0;
void kfunc_def(security_ib_free_security)(void *sec) = 0;

// CONFIG_SECURITY_NETWORK_XFRM
int kfunc_def(security_xfrm_policy_alloc)(struct xfrm_sec_ctx **ctxp, struct xfrm_user_sec_ctx *sec_ctx, gfp_t gfp) = 0;
int kfunc_def(security_xfrm_policy_clone)(struct xfrm_sec_ctx *old_ctx, struct xfrm_sec_ctx **new_ctxp) = 0;
void kfunc_def(security_xfrm_policy_free)(struct xfrm_sec_ctx *ctx) = 0;
int kfunc_def(security_xfrm_policy_delete)(struct xfrm_sec_ctx *ctx) = 0;
int kfunc_def(security_xfrm_state_alloc)(struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx) = 0;
int kfunc_def(security_xfrm_state_alloc_acquire)(struct xfrm_state *x, struct xfrm_sec_ctx *polsec, u32 secid) = 0;
int kfunc_def(security_xfrm_state_delete)(struct xfrm_state *x) = 0;
void kfunc_def(security_xfrm_state_free)(struct xfrm_state *x) = 0;
int kfunc_def(security_xfrm_policy_lookup)(struct xfrm_sec_ctx *ctx, u32 fl_secid) = 0;
int kfunc_def(security_xfrm_state_pol_flow_match)(struct xfrm_state *x, struct xfrm_policy *xp,
                                                  const struct flowi_common *flic) = 0;
int kfunc_def(security_xfrm_decode_session)(struct sk_buff *skb, u32 *secid) = 0;
void kfunc_def(security_skb_classify_flow)(struct sk_buff *skb, struct flowi_common *flic) = 0;

/* key management security hooks */
// CONFIG_KEYS
typedef void *key_ref_t;
int kfunc_def(security_key_alloc)(struct key *key, const struct cred *cred, unsigned long flags) = 0;
void kfunc_def(security_key_free)(struct key *key) = 0;
int kfunc_def(security_key_permission)(key_ref_t key_ref, const struct cred *cred, enum key_need_perm need_perm) = 0;
int kfunc_def(security_key_getsecurity)(struct key *key, char **_buffer) = 0;

// CONFIG_AUDIT
int kfunc_def(security_audit_rule_init)(u32 field, u32 op, char *rulestr, void **lsmrule) = 0;
int kfunc_def(security_audit_rule_known)(struct audit_krule *krule) = 0;
void kfunc_def(security_audit_rule_free)(void *lsmrule) = 0;
int kfunc_def(security_audit_rule_match)(u32 secid, u32 field, u32 op, void *lsmrule) = 0;

// CONFIG_BPF_SYSCALL
int kfunc_def(security_bpf)(int cmd, union bpf_attr *attr, unsigned int size) = 0;
int kfunc_def(security_bpf_map)(struct bpf_map *map, fmode_t fmode) = 0;
int kfunc_def(security_bpf_prog)(struct bpf_prog *prog) = 0;
int kfunc_def(security_bpf_map_alloc)(struct bpf_map *map) = 0;
int kfunc_def(security_bpf_prog_alloc)(struct bpf_prog_aux *aux) = 0;
void kfunc_def(security_bpf_map_free)(struct bpf_map *map) = 0;
void kfunc_def(security_bpf_prog_free)(struct bpf_prog_aux *aux) = 0;
// CONFIG_BPF_SYSCALL

int kfunc_def(security_locked_down)(enum lockdown_reason what) = 0;

// CONFIG_PERF_EVENTS
int kfunc_def(security_perf_event_open)(struct perf_event_attr *attr, int type) = 0;
int kfunc_def(security_perf_event_alloc)(struct perf_event *event) = 0;
void kfunc_def(security_perf_event_free)(struct perf_event *event) = 0;
int kfunc_def(security_perf_event_read)(struct perf_event *event) = 0;
int kfunc_def(security_perf_event_write)(struct perf_event *event) = 0;

// CONFIG_IO_URING
int kfunc_def(security_uring_override_creds)(const struct cred *new) = 0;
int kfunc_def(security_uring_sqpoll)(void) = 0;
int kfunc_def(security_uring_cmd)(struct io_uring_cmd *ioucmd) = 0;

void _linux_security_security_sym_match(const char *name, unsigned long addr)
{
    // kfunc_match(security_binder_set_context_mgr, name, addr);
    // kfunc_match(security_binder_transaction, name, addr);
    // kfunc_match(security_binder_transfer_binder, name, addr);
    // kfunc_match(security_binder_transfer_file, name, addr);
    // kfunc_match(security_ptrace_access_check, name, addr);
    // kfunc_match(security_ptrace_traceme, name, addr);
    // kfunc_match(security_capget, name, addr);
    // kfunc_match(security_capset, name, addr);
    // kfunc_match(security_capable, name, addr);
    // kfunc_match(security_quotactl, name, addr);
    // kfunc_match(security_quota_on, name, addr);
    // kfunc_match(security_syslog, name, addr);
    // kfunc_match(security_settime64, name, addr);
    // kfunc_match(security_vm_enough_memory_mm, name, addr);
    // kfunc_match(security_bprm_creds_for_exec, name, addr);
    // kfunc_match(security_bprm_creds_from_file, name, addr);
    // kfunc_match(security_bprm_check, name, addr);
    // kfunc_match(security_bprm_committing_creds, name, addr);
    // kfunc_match(security_bprm_committed_creds, name, addr);
    // kfunc_match(security_fs_context_dup, name, addr);
    // kfunc_match(security_fs_context_parse_param, name, addr);
    // kfunc_match(security_sb_alloc, name, addr);
    // kfunc_match(security_sb_delete, name, addr);
    // kfunc_match(security_sb_free, name, addr);
    // kfunc_match(security_free_mnt_opts, name, addr);
    // kfunc_match(security_sb_eat_lsm_opts, name, addr);
    // kfunc_match(security_sb_remount, name, addr);
    // kfunc_match(security_sb_kern_mount, name, addr);
    // kfunc_match(security_sb_show_options, name, addr);
    // kfunc_match(security_sb_statfs, name, addr);
    // kfunc_match(security_sb_mount, name, addr);
    // kfunc_match(security_sb_umount, name, addr);
    // kfunc_match(security_sb_pivotroot, name, addr);
    // kfunc_match(security_sb_set_mnt_opts, name, addr);
    // kfunc_match(security_sb_clone_mnt_opts, name, addr);
    // kfunc_match(security_add_mnt_opt, name, addr);
    // kfunc_match(security_move_mount, name, addr);
    // kfunc_match(security_dentry_init_security, name, addr);
    // kfunc_match(security_dentry_create_files_as, name, addr);

    // //CONFIG_SECURITY_PATH
    // kfunc_match(security_path_unlink, name, addr);
    // kfunc_match(security_path_mkdir, name, addr);
    // kfunc_match(security_path_rmdir, name, addr);
    // kfunc_match(security_path_mknod, name, addr);
    // kfunc_match(security_path_truncate, name, addr);
    // kfunc_match(security_path_symlink, name, addr);
    // kfunc_match(security_path_link, name, addr);
    // kfunc_match(security_path_rename, name, addr);
    // kfunc_match(security_path_chmod, name, addr);
    // kfunc_match(security_path_chown, name, addr);
    // kfunc_match(security_path_chroot, name, addr);
    // /* CONFIG_SECURITY_PATH */

    // /* Needed for inode based security check */
    // kfunc_match(security_path_notify, name, addr);
    // kfunc_match(security_inode_alloc, name, addr);
    // kfunc_match(security_inode_free, name, addr);
    // kfunc_match(security_inode_init_security, name, addr);
    // kfunc_match(security_old_inode_init_security, name, addr);
    // kfunc_match(security_inode_create, name, addr);
    // kfunc_match(security_inode_link, name, addr);
    // kfunc_match(security_inode_unlink, name, addr);
    // kfunc_match(security_inode_symlink, name, addr);
    // kfunc_match(security_inode_mkdir, name, addr);
    // kfunc_match(security_inode_rmdir, name, addr);
    // kfunc_match(security_inode_mknod, name, addr);
    // kfunc_match(security_inode_rename, name, addr);
    // kfunc_match(security_inode_readlink, name, addr);
    // kfunc_match(security_inode_follow_link, name, addr);
    // kfunc_match(security_inode_permission, name, addr);
    // kfunc_match(security_inode_setattr, name, addr);
    // kfunc_match(security_inode_getattr, name, addr);
    // kfunc_match(security_inode_setxattr, name, addr);
    // kfunc_match(security_inode_post_setxattr, name, addr);
    // kfunc_match(security_inode_getxattr, name, addr);
    // kfunc_match(security_inode_listxattr, name, addr);
    // kfunc_match(security_inode_removexattr, name, addr);
    // kfunc_match(security_inode_set_acl, name, addr);
    // kfunc_match(security_inode_get_acl, name, addr);
    // kfunc_match(security_inode_remove_acl, name, addr);
    // kfunc_match(security_inode_need_killpriv, name, addr);
    // kfunc_match(security_inode_killpriv, name, addr);
    // kfunc_match(security_inode_getsecurity, name, addr);
    // kfunc_match(security_inode_setsecurity, name, addr);
    // kfunc_match(security_inode_listsecurity, name, addr);
    // kfunc_match(security_inode_getsecid, name, addr);
    // kfunc_match(security_inode_copy_up, name, addr);
    // kfunc_match(security_inode_copy_up_xattr, name, addr);
    // kfunc_match(security_kernfs_init_security, name, addr);
    // kfunc_match(security_file_permission, name, addr);
    // kfunc_match(security_file_alloc, name, addr);
    // kfunc_match(security_file_free, name, addr);
    // kfunc_match(security_file_ioctl, name, addr);
    // kfunc_match(security_mmap_addr, name, addr);
    // kfunc_match(security_mmap_file, name, addr);
    // kfunc_match(security_file_mprotect, name, addr);
    // kfunc_match(security_file_lock, name, addr);
    // kfunc_match(security_file_fcntl, name, addr);
    // kfunc_match(security_file_set_fowner, name, addr);
    // kfunc_match(security_file_send_sigiotask, name, addr);
    // kfunc_match(security_file_receive, name, addr);
    // kfunc_match(security_file_open, name, addr);
    // kfunc_match(security_file_truncate, name, addr);
    // kfunc_match(security_task_alloc, name, addr);
    // kfunc_match(security_task_free, name, addr);
    // kfunc_match(security_cred_alloc_blank, name, addr);
    // kfunc_match(security_cred_free, name, addr);
    // kfunc_match(security_prepare_creds, name, addr);
    // kfunc_match(security_transfer_creds, name, addr);
    kfunc_match(security_cred_getsecid, name, addr);
    // kfunc_match(security_kernel_act_as, name, addr);
    // kfunc_match(security_kernel_create_files_as, name, addr);
    // kfunc_match(security_kernel_module_request, name, addr);
    // kfunc_match(security_kernel_load_data, name, addr);
    // kfunc_match(security_kernel_post_load_data, name, addr);
    // kfunc_match(security_kernel_read_file, name, addr);
    // kfunc_match(security_kernel_post_read_file, name, addr);
    // kfunc_match(security_task_fix_setuid, name, addr);
    // kfunc_match(security_task_fix_setgid, name, addr);
    // kfunc_match(security_task_fix_setgroups, name, addr);
    // kfunc_match(security_task_setpgid, name, addr);
    // kfunc_match(security_task_getpgid, name, addr);
    // kfunc_match(security_task_getsid, name, addr);
    // kfunc_match(security_current_getsecid_subj, name, addr);
    // kfunc_match(security_task_getsecid_obj, name, addr);
    // kfunc_match(security_task_getsecid, name, addr);
    // kfunc_match(security_task_setnice, name, addr);
    // kfunc_match(security_task_setioprio, name, addr);
    // kfunc_match(security_task_getioprio, name, addr);
    // kfunc_match(security_task_prlimit, name, addr);
    // kfunc_match(security_task_setrlimit, name, addr);
    // kfunc_match(security_task_setscheduler, name, addr);
    // kfunc_match(security_task_getscheduler, name, addr);
    // kfunc_match(security_task_movememory, name, addr);
    // kfunc_match(security_task_kill, name, addr);
    // kfunc_match(security_task_prctl, name, addr);
    // kfunc_match(security_task_to_inode, name, addr);
    // kfunc_match(security_create_user_ns, name, addr);
    // kfunc_match(security_ipc_permission, name, addr);
    // kfunc_match(security_ipc_getsecid, name, addr);
    // kfunc_match(security_msg_msg_alloc, name, addr);
    // kfunc_match(security_msg_msg_free, name, addr);
    // kfunc_match(security_msg_queue_alloc, name, addr);
    // kfunc_match(security_msg_queue_free, name, addr);
    // kfunc_match(security_msg_queue_associate, name, addr);
    // kfunc_match(security_msg_queue_msgctl, name, addr);
    // kfunc_match(security_msg_queue_msgsnd, name, addr);
    // kfunc_match(security_msg_queue_msgrcv, name, addr);
    // kfunc_match(security_shm_alloc, name, addr);
    // kfunc_match(security_shm_free, name, addr);
    // kfunc_match(security_shm_associate, name, addr);
    // kfunc_match(security_shm_shmctl, name, addr);
    // kfunc_match(security_shm_shmat, name, addr);
    // kfunc_match(security_sem_alloc, name, addr);
    // kfunc_match(security_sem_free, name, addr);
    // kfunc_match(security_sem_associate, name, addr);
    // kfunc_match(security_sem_semctl, name, addr);
    // kfunc_match(security_sem_semop, name, addr);
    // kfunc_match(security_d_instantiate, name, addr);
    // kfunc_match(security_getprocattr, name, addr);
    // kfunc_match(security_setprocattr, name, addr);
    // kfunc_match(security_netlink_send, name, addr);
    // kfunc_match(security_ismaclabel, name, addr);
    // kfunc_match(security_secid_to_secctx, name, addr);
    // kfunc_match(security_secctx_to_secid, name, addr);
    // kfunc_match(security_release_secctx, name, addr);
    // kfunc_match(security_inode_invalidate_secctx, name, addr);
    // kfunc_match(security_inode_notifysecctx, name, addr);
    // kfunc_match(security_inode_setsecctx, name, addr);
    // kfunc_match(security_inode_getsecctx, name, addr);

    // // CONFIG_WATCH_QUEUE
    // kfunc_match(security_post_notification, name, addr);

    // // CONFIG_KEY_NOTIFICATIONS
    // kfunc_match(security_watch_key, name, addr);

    // // CONFIG_SECURITY_NETWORK
    // kfunc_match(security_unix_stream_connect, name, addr);
    // kfunc_match(security_unix_may_send, name, addr);
    // kfunc_match(security_socket_create, name, addr);
    // kfunc_match(security_socket_post_create, name, addr);
    // kfunc_match(security_socket_socketpair, name, addr);
    // kfunc_match(security_socket_bind, name, addr);
    // kfunc_match(security_socket_connect, name, addr);
    // kfunc_match(security_socket_listen, name, addr);
    // kfunc_match(security_socket_accept, name, addr);
    // kfunc_match(security_socket_sendmsg, name, addr);
    // kfunc_match(security_socket_recvmsg, name, addr);
    // kfunc_match(security_socket_getsockname, name, addr);
    // kfunc_match(security_socket_getpeername, name, addr);
    // kfunc_match(security_socket_getsockopt, name, addr);
    // kfunc_match(security_socket_setsockopt, name, addr);
    // kfunc_match(security_socket_shutdown, name, addr);
    // kfunc_match(security_sock_rcv_skb, name, addr);
    // kfunc_match(security_socket_getpeersec_stream, name, addr);
    // kfunc_match(security_socket_getpeersec_dgram, name, addr);
    // kfunc_match(security_sk_alloc, name, addr);
    // kfunc_match(security_sk_free, name, addr);
    // kfunc_match(security_sk_clone, name, addr);
    // kfunc_match(security_sk_classify_flow, name, addr);
    // kfunc_match(security_req_classify_flow, name, addr);
    // kfunc_match(security_sock_graft, name, addr);
    // kfunc_match(security_inet_conn_request, name, addr);
    // kfunc_match(security_inet_csk_clone, name, addr);
    // kfunc_match(security_inet_conn_established, name, addr);
    // kfunc_match(security_secmark_relabel_packet, name, addr);
    // kfunc_match(security_secmark_refcount_inc, name, addr);
    // kfunc_match(security_secmark_refcount_dec, name, addr);
    // kfunc_match(security_tun_dev_alloc_security, name, addr);
    // kfunc_match(security_tun_dev_free_security, name, addr);
    // kfunc_match(security_tun_dev_create, name, addr);
    // kfunc_match(security_tun_dev_attach_queue, name, addr);
    // kfunc_match(security_tun_dev_attach, name, addr);
    // kfunc_match(security_tun_dev_open, name, addr);
    // kfunc_match(security_sctp_assoc_request, name, addr);
    // kfunc_match(security_sctp_bind_connect, name, addr);
    // kfunc_match(security_sctp_sk_clone, name, addr);
    // kfunc_match(security_sctp_assoc_established, name, addr);

    // // CONFIG_SECURITY_INFINIBAND
    // kfunc_match(security_ib_pkey_access, name, addr);
    // kfunc_match(security_ib_endport_manage_subnet, name, addr);
    // kfunc_match(security_ib_alloc_security, name, addr);
    // kfunc_match(security_ib_free_security, name, addr);

    // // CONFIG_SECURITY_NETWORK_XFRM
    // kfunc_match(security_xfrm_policy_alloc, name, addr);
    // kfunc_match(security_xfrm_policy_clone, name, addr);
    // kfunc_match(security_xfrm_policy_free, name, addr);
    // kfunc_match(security_xfrm_policy_delete, name, addr);
    // kfunc_match(security_xfrm_state_alloc, name, addr);
    // kfunc_match(security_xfrm_state_alloc_acquire, name, addr);
    // kfunc_match(security_xfrm_state_delete, name, addr);
    // kfunc_match(security_xfrm_state_free, name, addr);
    // kfunc_match(security_xfrm_policy_lookup, name, addr);
    // kfunc_match(security_xfrm_state_pol_flow_match, name, addr);
    // kfunc_match(security_xfrm_decode_session, name, addr);
    // kfunc_match(security_skb_classify_flow, name, addr);

    // /* key management security hooks */
    // // CONFIG_KEYS
    // kfunc_match(security_key_alloc, name, addr);
    // kfunc_match(security_key_free, name, addr);
    // kfunc_match(security_key_permission, name, addr);
    // kfunc_match(security_key_getsecurity, name, addr);

    // // CONFIG_AUDIT
    // kfunc_match(security_audit_rule_init, name, addr);
    // kfunc_match(security_audit_rule_known, name, addr);
    // kfunc_match(security_audit_rule_free, name, addr);
    // kfunc_match(security_audit_rule_match, name, addr);

    // // CONFIG_BPF_SYSCALL
    // kfunc_match(security_bpf, name, addr);
    // kfunc_match(security_bpf_map, name, addr);
    // kfunc_match(security_bpf_prog, name, addr);
    // kfunc_match(security_bpf_map_alloc, name, addr);
    // kfunc_match(security_bpf_prog_alloc, name, addr);
    // kfunc_match(security_bpf_map_free, name, addr);
    // kfunc_match(security_bpf_prog_free, name, addr);
    // // CONFIG_BPF_SYSCALL

    // kfunc_match(security_locked_down, name, addr);

    // // CONFIG_PERF_EVENTS
    // kfunc_match(security_perf_event_open, name, addr);
    // kfunc_match(security_perf_event_alloc, name, addr);
    // kfunc_match(security_perf_event_free, name, addr);
    // kfunc_match(security_perf_event_read, name, addr);
    // kfunc_match(security_perf_event_write, name, addr);

    // // CONFIG_IO_URING
    // kfunc_match(security_uring_override_creds, name, addr);
    // kfunc_match(security_uring_sqpoll, name, addr);
    // kfunc_match(security_uring_cmd, name, addr);
}
