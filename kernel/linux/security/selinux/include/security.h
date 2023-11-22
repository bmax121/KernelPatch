#ifndef _SELINUX_SECURITY_H_
#define _SELINUX_SECURITY_H_

#include <ktypes.h>
#include <ksyms.h>
#include <common.h>

#define SECSID_NULL 0x00000000 /* unspecified SID */
#define SECSID_WILD 0xffffffff /* wildcard SID */
#define SECCLASS_NULL 0x0000 /* no class */

/* Identify specific policy version changes */
#define POLICYDB_VERSION_BASE 15
#define POLICYDB_VERSION_BOOL 16
#define POLICYDB_VERSION_IPV6 17
#define POLICYDB_VERSION_NLCLASS 18
#define POLICYDB_VERSION_VALIDATETRANS 19
#define POLICYDB_VERSION_MLS 19
#define POLICYDB_VERSION_AVTAB 20
#define POLICYDB_VERSION_RANGETRANS 21
#define POLICYDB_VERSION_POLCAP 22
#define POLICYDB_VERSION_PERMISSIVE 23
#define POLICYDB_VERSION_BOUNDARY 24
#define POLICYDB_VERSION_FILENAME_TRANS 25
#define POLICYDB_VERSION_ROLETRANS 26
#define POLICYDB_VERSION_NEW_OBJECT_DEFAULTS 27
#define POLICYDB_VERSION_DEFAULT_TYPE 28
#define POLICYDB_VERSION_CONSTRAINT_NAMES 29
#define POLICYDB_VERSION_XPERMS_IOCTL 30
#define POLICYDB_VERSION_INFINIBAND 31
#define POLICYDB_VERSION_GLBLUB 32
#define POLICYDB_VERSION_COMP_FTRANS 33 /* compressed filename transitions */

/* Range of policy versions we understand*/
#define POLICYDB_VERSION_MIN POLICYDB_VERSION_BASE
#define POLICYDB_VERSION_MAX POLICYDB_VERSION_COMP_FTRANS

/* Mask for just the mount related flags */
#define SE_MNTMASK 0x0f
/* Super block security struct flags for mount options */
/* BE CAREFUL, these need to be the low order bits for selinux_get_mnt_opts */
#define CONTEXT_MNT 0x01
#define FSCONTEXT_MNT 0x02
#define ROOTCONTEXT_MNT 0x04
#define DEFCONTEXT_MNT 0x08
#define SBLABEL_MNT 0x10
/* Non-mount related flags */
#define SE_SBINITIALIZED 0x0100
#define SE_SBPROC 0x0200
#define SE_SBGENFS 0x0400
#define SE_SBGENFS_XATTR 0x0800

#define CONTEXT_STR "context"
#define FSCONTEXT_STR "fscontext"
#define ROOTCONTEXT_STR "rootcontext"
#define DEFCONTEXT_STR "defcontext"
#define SECLABEL_STR "seclabel"

struct selinux_policy;
struct selinux_policy_convert_data;

struct selinux_load_state
{
    struct selinux_policy *policy;
    struct selinux_policy_convert_data *convert_data;
};

#define SEL_VEC_MAX 32
struct av_decision
{
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

#define XPERMS_ALLOWED 1
#define XPERMS_AUDITALLOW 2
#define XPERMS_DONTAUDIT 4

#define security_xperm_set(perms, x) ((perms)[(x) >> 5] |= 1 << ((x) & 0x1f))
#define security_xperm_test(perms, x) (1 & ((perms)[(x) >> 5] >> ((x) & 0x1f)))

struct extended_perms_data
{
    u32 p[8];
};

struct extended_perms_decision
{
    u8 used;
    u8 driver;
    struct extended_perms_data *allowed;
    struct extended_perms_data *auditallow;
    struct extended_perms_data *dontaudit;
};

struct extended_perms
{
    u16 len; /* length associated decision chain */
    struct extended_perms_data drivers; /* flag drivers that are used */
};

/* definitions of av_decision.flags */
#define AVD_FLAGS_PERMISSIVE 0x0001

struct qstr;
struct super_block;
struct netlbl_lsm_secattr;

#define SECURITY_FS_USE_XATTR 1 /* use xattr */
#define SECURITY_FS_USE_TRANS 2 /* use transition SIDs, e.g. devpts/tmpfs */
#define SECURITY_FS_USE_TASK 3 /* use task SIDs, e.g. pipefs/sockfs */
#define SECURITY_FS_USE_GENFS 4 /* use the genfs support */
#define SECURITY_FS_USE_NONE 5 /* no labeling support */
#define SECURITY_FS_USE_MNTPOINT 6 /* use mountpoint labeling */
#define SECURITY_FS_USE_NATIVE 7 /* use native label support */
#define SECURITY_FS_USE_MAX 7 /* Highest SECURITY_FS_USE_XXX */

#define SELINUX_KERNEL_STATUS_VERSION 1
struct selinux_kernel_status
{
    u32 version; /* version number of the structure */
    u32 sequence; /* sequence number of seqlock logic */
    u32 enforcing; /* current setting of enforcing mode */
    u32 policyload; /* times of policy reloaded */
    u32 deny_unknown; /* current setting of deny_unknown */
    /*
	 * The version > 0 supports above members.
	 */
} __packed;

extern int kvar_def(selinux_enabled_boot);
extern struct selinux_state kvar_def(selinux_state);
extern int kvar_def(selinux_enabled);

extern int kfunc_def(security_mls_enabled)(void);
extern int kfunc_def(security_load_policy)(void *data, size_t len, struct selinux_load_state *load_state);
extern void kfunc_def(selinux_policy_commit)(struct selinux_load_state *load_state);
extern void kfunc_def(selinux_policy_cancel)(struct selinux_load_state *load_state);
extern int kfunc_def(security_read_policy)(void **data, size_t *len);
extern int kfunc_def(security_read_state_kernel)(void **data, size_t *len);
extern int kfunc_def(security_policycap_supported)(unsigned int req_cap);
extern void kfunc_def(security_compute_av)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd,
                                           struct extended_perms *xperms);
extern void kfunc_def(security_compute_xperms_decision)(u32 ssid, u32 tsid, u16 tclass, u8 driver,
                                                        struct extended_perms_decision *xpermd);
extern void kfunc_def(security_compute_av_user)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);
extern int kfunc_def(security_transition_sid)(u32 ssid, u32 tsid, u16 tclass, const struct qstr *qstr, u32 *out_sid);
extern int kfunc_def(security_transition_sid_user)(u32 ssid, u32 tsid, u16 tclass, const char *objname, u32 *out_sid);
extern int kfunc_def(security_member_sid)(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid);
extern int kfunc_def(security_change_sid)(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid);
extern int kfunc_def(security_sid_to_context)(u32 sid, char **scontext, u32 *scontext_len);
extern int kfunc_def(security_sid_to_context_force)(u32 sid, char **scontext, u32 *scontext_len);
extern int kfunc_def(security_sid_to_context_inval)(u32 sid, char **scontext, u32 *scontext_len);
extern int kfunc_def(security_context_to_sid)(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
extern int kfunc_def(security_context_str_to_sid)(const char *scontext, u32 *out_sid, gfp_t gfp);
extern int kfunc_def(security_context_to_sid_default)(const char *scontext, u32 scontext_len, u32 *out_sid, u32 def_sid,
                                                      gfp_t gfp_flags);
extern int kfunc_def(security_context_to_sid_force)(const char *scontext, u32 scontext_len, u32 *sid);
extern int kfunc_def(security_get_user_sids)(u32 callsid, char *username, u32 **sids, u32 *nel);
extern int kfunc_def(security_port_sid)(u8 protocol, u16 port, u32 *out_sid);
extern int kfunc_def(security_ib_pkey_sid)(u64 subnet_prefix, u16 pkey_num, u32 *out_sid);
extern int kfunc_def(security_ib_endport_sid)(const char *dev_name, u8 port_num, u32 *out_sid);
extern int kfunc_def(security_netif_sid)(char *name, u32 *if_sid);
extern int kfunc_def(security_node_sid)(u16 domain, void *addr, u32 addrlen, u32 *out_sid);
extern int kfunc_def(security_validate_transition)(u32 oldsid, u32 newsid, u32 tasksid, u16 tclass);
extern int kfunc_def(security_validate_transition_user)(u32 oldsid, u32 newsid, u32 tasksid, u16 tclass);
extern int kfunc_def(security_bounded_transition)(u32 oldsid, u32 newsid);
extern int kfunc_def(security_sid_mls_copy)(u32 sid, u32 mls_sid, u32 *new_sid);
extern int kfunc_def(security_net_peersid_resolve)(u32 nlbl_sid, u32 nlbl_type, u32 xfrm_sid, u32 *peer_sid);
extern int kfunc_def(security_get_classes)(struct selinux_policy *policy, char ***classes, int *nclasses);
extern int kfunc_def(security_get_permissions)(struct selinux_policy *policy, char *class, char ***perms, int *nperms);
extern int kfunc_def(security_get_reject_unknown)(void);
extern int kfunc_def(security_get_allow_unknown)(void);

extern int kfunc_def(security_fs_use)(struct super_block *sb);
extern int kfunc_def(security_genfs_sid)(const char *fstype, const char *path, u16 sclass, u32 *sid);
extern int kfunc_def(selinux_policy_genfs_sid)(struct selinux_policy *policy, const char *fstype, const char *path,
                                               u16 sclass, u32 *sid);
extern int kfunc_def(security_netlbl_secattr_to_sid)(struct netlbl_lsm_secattr *secattr, u32 *sid);
extern int kfunc_def(security_netlbl_sid_to_secattr)(u32 sid, struct netlbl_lsm_secattr *secattr);
extern const char *kfunc_def(security_get_initial_sid_context)(u32 sid);

extern void kfunc_def(selinux_status_update_setenforce)(int enforcing);
extern void kfunc_def(selinux_status_update_policyload)(int seqno);
extern void kfunc_def(selinux_complete_init)(void);
extern void kfunc_def(exit_sel_fs)(void);
extern void kfunc_def(selnl_notify_setenforce)(int val);
extern void kfunc_def(selnl_notify_policyload)(u32 seqno);
extern int kfunc_def(selinux_nlmsg_lookup)(u16 sclass, u16 nlmsg_type, u32 *perm);

extern void kfunc_def(avtab_cache_init)(void);
extern void kfunc_def(ebitmap_cache_init)(void);
extern void kfunc_def(hashtab_cache_init)(void);
extern int kfunc_def(security_sidtab_hash_stats)(char *page);

// version compat

#define selinux_compat_def(func) (*selinux_compat_kf_##func##_t)

typedef int selinux_compat_def(security_mls_enabled)(struct selinux_state *state);
typedef int selinux_compat_def(security_load_policy)(struct selinux_state *state, void *data, size_t len,
                                                     struct selinux_load_state *load_state);
typedef void selinux_compat_def(selinux_policy_commit)(struct selinux_state *state,
                                                       struct selinux_load_state *load_state);
typedef void selinux_compat_def(selinux_policy_cancel)(struct selinux_state *state,
                                                       struct selinux_load_state *load_state);
typedef int selinux_compat_def(security_read_policy)(struct selinux_state *state, void **data, size_t *len);
typedef int selinux_compat_def(security_read_state_kernel)(struct selinux_state *state, void **data, size_t *len);
typedef int selinux_compat_def(security_policycap_supported)(struct selinux_state *state, unsigned int req_cap);
typedef void selinux_compat_def(security_compute_av)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
                                                     struct av_decision *avd, struct extended_perms *xperms);
typedef void selinux_compat_def(security_compute_xperms_decision)(struct selinux_state *state, u32 ssid, u32 tsid,
                                                                  u16 tclass, u8 driver,
                                                                  struct extended_perms_decision *xpermd);
typedef void selinux_compat_def(security_compute_av_user)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
                                                          struct av_decision *avd);
typedef int selinux_compat_def(security_transition_sid)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
                                                        const struct qstr *qstr, u32 *out_sid);
typedef int selinux_compat_def(security_transition_sid_user)(struct selinux_state *state, u32 ssid, u32 tsid,
                                                             u16 tclass, const char *objname, u32 *out_sid);
typedef int selinux_compat_def(security_member_sid)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
                                                    u32 *out_sid);
typedef int selinux_compat_def(security_change_sid)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
                                                    u32 *out_sid);
typedef int selinux_compat_def(security_sid_to_context)(struct selinux_state *state, u32 sid, char **scontext,
                                                        u32 *scontext_len);
typedef int selinux_compat_def(security_sid_to_context_force)(struct selinux_state *state, u32 sid, char **scontext,
                                                              u32 *scontext_len);
typedef int selinux_compat_def(security_sid_to_context_inval)(struct selinux_state *state, u32 sid, char **scontext,
                                                              u32 *scontext_len);
typedef int selinux_compat_def(security_context_to_sid)(struct selinux_state *state, const char *scontext,
                                                        u32 scontext_len, u32 *out_sid, gfp_t gfp);
typedef int selinux_compat_def(security_context_str_to_sid)(struct selinux_state *state, const char *scontext,
                                                            u32 *out_sid, gfp_t gfp);
typedef int selinux_compat_def(security_context_to_sid_default)(struct selinux_state *state, const char *scontext,
                                                                u32 scontext_len, u32 *out_sid, u32 def_sid,
                                                                gfp_t gfp_flags);
typedef int selinux_compat_def(security_context_to_sid_force)(struct selinux_state *state, const char *scontext,
                                                              u32 scontext_len, u32 *sid);
typedef int selinux_compat_def(security_get_user_sids)(struct selinux_state *state, u32 callsid, char *username,
                                                       u32 **sids, u32 *nel);
typedef int selinux_compat_def(security_port_sid)(struct selinux_state *state, u8 protocol, u16 port, u32 *out_sid);
typedef int selinux_compat_def(security_ib_pkey_sid)(struct selinux_state *state, u64 subnet_prefix, u16 pkey_num,
                                                     u32 *out_sid);
typedef int selinux_compat_def(security_ib_endport_sid)(struct selinux_state *state, const char *dev_name, u8 port_num,
                                                        u32 *out_sid);
typedef int selinux_compat_def(security_netif_sid)(struct selinux_state *state, char *name, u32 *if_sid);
typedef int selinux_compat_def(security_node_sid)(struct selinux_state *state, u16 domain, void *addr, u32 addrlen,
                                                  u32 *out_sid);
typedef int selinux_compat_def(security_validate_transition)(struct selinux_state *state, u32 oldsid, u32 newsid,
                                                             u32 tasksid, u16 tclass);
typedef int selinux_compat_def(security_validate_transition_user)(struct selinux_state *state, u32 oldsid, u32 newsid,
                                                                  u32 tasksid, u16 tclass);
typedef int selinux_compat_def(security_bounded_transition)(struct selinux_state *state, u32 oldsid, u32 newsid);
typedef int selinux_compat_def(security_sid_mls_copy)(struct selinux_state *state, u32 sid, u32 mls_sid, u32 *new_sid);
typedef int selinux_compat_def(security_net_peersid_resolve)(struct selinux_state *state, u32 nlbl_sid, u32 nlbl_type,
                                                             u32 xfrm_sid, u32 *peer_sid);
typedef int selinux_compat_def(security_get_classes)(struct selinux_state *state, struct selinux_policy *policy,
                                                     char ***classes, int *nclasses);
typedef int selinux_compat_def(security_get_permissions)(struct selinux_state *state, struct selinux_policy *policy,
                                                         char *class, char ***perms, int *nperms);
typedef int selinux_compat_def(security_get_reject_unknown)(struct selinux_state *state);
typedef int selinux_compat_def(security_get_allow_unknown)(struct selinux_state *state);

typedef int selinux_compat_def(security_fs_use)(struct selinux_state *state, struct super_block *sb);
typedef int selinux_compat_def(security_genfs_sid)(struct selinux_state *state, const char *fstype, const char *path,
                                                   u16 sclass, u32 *sid);
typedef int selinux_compat_def(selinux_policy_genfs_sid)(struct selinux_state *state, struct selinux_policy *policy,
                                                         const char *fstype, const char *path, u16 sclass, u32 *sid);
typedef int selinux_compat_def(security_netlbl_secattr_to_sid)(struct selinux_state *state,
                                                               struct netlbl_lsm_secattr *secattr, u32 *sid);
typedef int selinux_compat_def(security_netlbl_sid_to_secattr)(struct selinux_state *state, u32 sid,
                                                               struct netlbl_lsm_secattr *secattr);
typedef const char *selinux_compat_def(security_get_initial_sid_context)(struct selinux_state *state, u32 sid);

typedef void selinux_compat_def(selinux_status_update_setenforce)(struct selinux_state *state, int enforcing);
typedef void selinux_compat_def(selinux_status_update_policyload)(struct selinux_state *state, int seqno);
typedef void selinux_compat_def(selinux_complete_init)(struct selinux_state *state);
typedef void selinux_compat_def(exit_sel_fs)(struct selinux_state *state);
typedef void selinux_compat_def(selnl_notify_setenforce)(struct selinux_state *state, int val);
typedef void selinux_compat_def(selnl_notify_policyload)(struct selinux_state *state, u32 seqno);
typedef int selinux_compat_def(selinux_nlmsg_lookup)(struct selinux_state *state, u16 sclass, u16 nlmsg_type,
                                                     u32 *perm);

typedef void selinux_compat_def(avtab_cache_init)(struct selinux_state *state);
typedef void selinux_compat_def(ebitmap_cache_init)(struct selinux_state *state);
typedef void selinux_compat_def(hashtab_cache_init)(struct selinux_state *state);
typedef int selinux_compat_def(security_sidtab_hash_stats)(struct selinux_state *state, char *page);

//

static inline bool selinux_has_selinux_state()
{
    return kvar(selinux_state) != 0;
}

static inline bool selinux_need_call_compat()
{
    return kver >= VERSION(4, 17, 0) && kver < VERSION(6, 4, 0);
}

#define selinux_compat_call_kfunc(func, ...) \
    ((selinux_compat_kf_##func##_t)kfunc(func))(kvar(selinux_state), ##__VA_ARGS__)

#define selinux_adapt_kfunc_call(func, ...)                        \
    if (kfunc(func)) {                                             \
        if (selinux_need_call_compat())                            \
            return selinux_compat_call_kfunc(func, ##__VA_ARGS__); \
        else                                                       \
            return kfunc(func)(__VA_ARGS__);                       \
    }

#define selinux_adapt_kfunc_call_void(func, ...)            \
    if (kfunc(func)) {                                      \
        if (selinux_need_call_compat())                     \
            selinux_compat_call_kfunc(func, ##__VA_ARGS__); \
        else                                                \
            kfunc(func)(__VA_ARGS__);                       \
    }

static inline int security_mls_enabled(void)
{
    selinux_adapt_kfunc_call(security_mls_enabled);
    kfunc_not_found();
    return 0;
}
static inline int security_load_policy(void *data, size_t len, struct selinux_load_state *load_state)
{
    selinux_adapt_kfunc_call(security_load_policy, data, len, load_state);
    kfunc_not_found();
    return 0;
}
static inline void selinux_policy_commit(struct selinux_load_state *load_state)
{
    selinux_adapt_kfunc_call_void(selinux_policy_commit, load_state);
    kfunc_not_found();
}
static inline void selinux_policy_cancel(struct selinux_load_state *load_state)
{
    selinux_adapt_kfunc_call_void(selinux_policy_cancel, load_state);
    kfunc_not_found();
}
static inline int security_read_policy(void **data, size_t *len)
{
    selinux_adapt_kfunc_call(security_read_policy, data, len);
    kfunc_not_found();
    return 0;
}
static inline int security_read_state_kernel(void **data, size_t *len)
{
    selinux_adapt_kfunc_call(security_read_state_kernel, data, len);
    kfunc_not_found();
    return 0;
}
static inline int security_policycap_supported(unsigned int req_cap)
{
    selinux_adapt_kfunc_call(security_policycap_supported, req_cap);
    kfunc_not_found();
    return 0;
}
static inline void security_compute_av(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd,
                                       struct extended_perms *xperms)
{
    selinux_adapt_kfunc_call_void(security_compute_av, ssid, tsid, tclass, avd, xperms);
    kfunc_not_found();
}
static inline void security_compute_xperms_decision(u32 ssid, u32 tsid, u16 tclass, u8 driver,
                                                    struct extended_perms_decision *xpermd)
{
    selinux_adapt_kfunc_call_void(security_compute_xperms_decision, ssid, tsid, tclass, driver, xpermd);
    kfunc_not_found();
}
static inline void security_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
    selinux_adapt_kfunc_call(security_compute_av_user, ssid, tsid, tclass, avd);
    kfunc_not_found();
}
static inline int security_transition_sid(u32 ssid, u32 tsid, u16 tclass, const struct qstr *qstr, u32 *out_sid)
{
    selinux_adapt_kfunc_call(security_transition_sid, ssid, tsid, tclass, qstr, out_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_transition_sid_user(u32 ssid, u32 tsid, u16 tclass, const char *objname, u32 *out_sid)
{
    selinux_adapt_kfunc_call(security_transition_sid_user, ssid, tsid, tclass, objname, out_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_member_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid)
{
    selinux_adapt_kfunc_call(security_member_sid, ssid, tsid, tclass, out_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_change_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid)
{
    selinux_adapt_kfunc_call(security_change_sid, ssid, tsid, tclass, out_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
{
    selinux_adapt_kfunc_call(security_sid_to_context, sid, scontext, scontext_len);
    kfunc_not_found();
    return 0;
}
static inline int security_sid_to_context_force(u32 sid, char **scontext, u32 *scontext_len)
{
    selinux_adapt_kfunc_call(security_sid_to_context_force, sid, scontext, scontext_len);
    kfunc_not_found();
    return 0;
}
static inline int security_sid_to_context_inval(u32 sid, char **scontext, u32 *scontext_len)
{
    selinux_adapt_kfunc_call(security_sid_to_context_inval, sid, scontext, scontext_len);
    kfunc_not_found();
    return 0;
}
static inline int security_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp)
{
    selinux_adapt_kfunc_call(security_context_to_sid, scontext, scontext_len, out_sid, gfp);
    kfunc_not_found();
    return 0;
}
static inline int security_context_str_to_sid(const char *scontext, u32 *out_sid, gfp_t gfp)
{
    selinux_adapt_kfunc_call(security_context_str_to_sid, scontext, out_sid, gfp);
    kfunc_not_found();
    return 0;
}
static inline int security_context_to_sid_default(const char *scontext, u32 scontext_len, u32 *out_sid, u32 def_sid,
                                                  gfp_t gfp_flags)
{
    selinux_adapt_kfunc_call(security_context_to_sid_default, scontext, scontext_len, out_sid, def_sid, gfp_flags);
    kfunc_not_found();
    return 0;
}
static inline int security_context_to_sid_force(const char *scontext, u32 scontext_len, u32 *sid)
{
    selinux_adapt_kfunc_call(security_context_to_sid_force, scontext, scontext_len, sid);
    kfunc_not_found();
    return 0;
}
static inline int security_get_user_sids(u32 callsid, char *username, u32 **sids, u32 *nel)
{
    selinux_adapt_kfunc_call(security_get_user_sids, callsid, username, sids, nel);
    kfunc_not_found();
    return 0;
}
static inline int security_port_sid(u8 protocol, u16 port, u32 *out_sid)
{
    selinux_adapt_kfunc_call(security_port_sid, protocol, port, out_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_ib_pkey_sid(u64 subnet_prefix, u16 pkey_num, u32 *out_sid)
{
    selinux_adapt_kfunc_call(security_ib_pkey_sid, subnet_prefix, pkey_num, out_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_ib_endport_sid(const char *dev_name, u8 port_num, u32 *out_sid)
{
    selinux_adapt_kfunc_call(security_ib_endport_sid, dev_name, port_num, out_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_netif_sid(char *name, u32 *if_sid)
{
    selinux_adapt_kfunc_call(security_netif_sid, name, if_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_node_sid(u16 domain, void *addr, u32 addrlen, u32 *out_sid)
{
    selinux_adapt_kfunc_call(security_node_sid, domain, addr, addrlen, out_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_validate_transition(u32 oldsid, u32 newsid, u32 tasksid, u16 tclass)
{
    selinux_adapt_kfunc_call(security_validate_transition, oldsid, newsid, tasksid, tclass);
    kfunc_not_found();
    return 0;
}
static inline int security_validate_transition_user(u32 oldsid, u32 newsid, u32 tasksid, u16 tclass)
{
    selinux_adapt_kfunc_call(security_validate_transition_user, oldsid, newsid, tasksid, tclass);
    kfunc_not_found();
    return 0;
}
static inline int security_bounded_transition(u32 oldsid, u32 newsid)
{
    selinux_adapt_kfunc_call(security_bounded_transition, oldsid, newsid);
    kfunc_not_found();
    return 0;
}
static inline int security_sid_mls_copy(u32 sid, u32 mls_sid, u32 *new_sid)
{
    selinux_adapt_kfunc_call(security_sid_mls_copy, sid, mls_sid, new_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_net_peersid_resolve(u32 nlbl_sid, u32 nlbl_type, u32 xfrm_sid, u32 *peer_sid)
{
    selinux_adapt_kfunc_call(security_net_peersid_resolve, nlbl_sid, nlbl_type, xfrm_sid, peer_sid);
    kfunc_not_found();
    return 0;
}
static inline int security_get_classes(struct selinux_policy *policy, char ***classes, int *nclasses)
{
    selinux_adapt_kfunc_call(security_get_classes, policy, classes, nclasses);
    kfunc_not_found();
    return 0;
}
static inline int security_get_permissions(struct selinux_policy *policy, char *class, char ***perms, int *nperms)
{
    selinux_adapt_kfunc_call(security_get_permissions, policy, class, perms, nperms);
    kfunc_not_found();
    return 0;
}
static inline int security_get_reject_unknown(void)
{
    selinux_adapt_kfunc_call(security_get_reject_unknown);
    kfunc_not_found();
    return 0;
}
static inline int security_get_allow_unknown(void)
{
    selinux_adapt_kfunc_call(security_get_allow_unknown);
    kfunc_not_found();
    return 0;
}

static inline int security_fs_use(struct super_block *sb)
{
    selinux_adapt_kfunc_call(security_fs_use, sb);
    kfunc_not_found();
    return 0;
}
static inline int security_genfs_sid(const char *fstype, const char *path, u16 sclass, u32 *sid)
{
    selinux_adapt_kfunc_call(security_genfs_sid, fstype, path, sclass, sid);
    kfunc_not_found();
    return 0;
}
static inline int selinux_policy_genfs_sid(struct selinux_policy *policy, const char *fstype, const char *path,
                                           u16 sclass, u32 *sid)
{
    selinux_adapt_kfunc_call(selinux_policy_genfs_sid, policy, fstype, path, sclass, sid);
    kfunc_not_found();
    return 0;
}
static inline int security_netlbl_secattr_to_sid(struct netlbl_lsm_secattr *secattr, u32 *sid)
{
    selinux_adapt_kfunc_call(security_netlbl_secattr_to_sid, secattr, sid);
    kfunc_not_found();
    return 0;
}
static inline int security_netlbl_sid_to_secattr(u32 sid, struct netlbl_lsm_secattr *secattr)
{
    selinux_adapt_kfunc_call(security_netlbl_sid_to_secattr, sid, secattr);
    kfunc_not_found();
    return 0;
}
static inline const char *security_get_initial_sid_context(u32 sid)
{
    selinux_adapt_kfunc_call(security_get_initial_sid_context, sid);
    kfunc_not_found();
    return 0;
}

static inline void selinux_status_update_setenforce(int enforcing)
{
    selinux_adapt_kfunc_call_void(selinux_status_update_setenforce, enforcing);
    kfunc_not_found();
}
static inline void selinux_status_update_policyload(int seqno)
{
    selinux_adapt_kfunc_call_void(selinux_status_update_policyload, seqno);
    kfunc_not_found();
}
static inline void selinux_complete_init(void)
{
    selinux_adapt_kfunc_call_void(selinux_complete_init);
    kfunc_not_found();
}
static inline void exit_sel_fs(void)
{
    selinux_adapt_kfunc_call_void(exit_sel_fs);
    kfunc_not_found();
}
static inline void selnl_notify_setenforce(int val)
{
    selinux_adapt_kfunc_call_void(selnl_notify_setenforce, val);
    kfunc_not_found();
}
static inline void selnl_notify_policyload(u32 seqno)
{
    selinux_adapt_kfunc_call_void(selnl_notify_policyload, seqno);
    kfunc_not_found();
}
static inline int selinux_nlmsg_lookup(u16 sclass, u16 nlmsg_type, u32 *perm)
{
    selinux_adapt_kfunc_call(selinux_nlmsg_lookup, sclass, nlmsg_type, perm);
    kfunc_not_found();
    return 0;
}

static inline void avtab_cache_init(void)
{
    selinux_adapt_kfunc_call_void(avtab_cache_init);
    kfunc_not_found();
}
static inline void ebitmap_cache_init(void)
{
    selinux_adapt_kfunc_call_void(ebitmap_cache_init);
    kfunc_not_found();
}
static inline void hashtab_cache_init(void)
{
    selinux_adapt_kfunc_call_void(hashtab_cache_init);
    kfunc_not_found();
}
static inline int security_sidtab_hash_stats(char *page)
{
    selinux_adapt_kfunc_call(security_sidtab_hash_stats, page);
    kfunc_not_found();
    return 0;
}

#endif