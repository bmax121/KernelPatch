#include <ksyms.h>
#include <ktypes.h>

#include <security/selinux/include/security.h>
#include <security/selinux/include/classmap.h>

int kvar_def(selinux_enabled_boot) = 0;
int kvar_def(selinux_enabled) = 0;
struct selinux_state kvar_def(selinux_state) = 0;
struct security_class_mapping kvar_def(secclass_map)[] = 0;

int kfunc_def(security_mls_enabled)(void) = 0;
int kfunc_def(security_load_policy)(void *data, size_t len, struct selinux_load_state *load_state) = 0;
void kfunc_def(selinux_policy_commit)(struct selinux_load_state *load_state) = 0;
void kfunc_def(selinux_policy_cancel)(struct selinux_load_state *load_state) = 0;
int kfunc_def(security_read_policy)(void **data, size_t *len) = 0;
int kfunc_def(security_read_state_kernel)(void **data, size_t *len) = 0;
int kfunc_def(security_policycap_supported)(unsigned int req_cap) = 0;
void kfunc_def(security_compute_av)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd,
                                    struct extended_perms *xperms) = 0;
void kfunc_def(security_compute_xperms_decision)(u32 ssid, u32 tsid, u16 tclass, u8 driver,
                                                 struct extended_perms_decision *xpermd) = 0;
void kfunc_def(security_compute_av_user)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd) = 0;
int kfunc_def(security_transition_sid)(u32 ssid, u32 tsid, u16 tclass, const struct qstr *qstr, u32 *out_sid) = 0;
int kfunc_def(security_transition_sid_user)(u32 ssid, u32 tsid, u16 tclass, const char *objname, u32 *out_sid) = 0;
int kfunc_def(security_member_sid)(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid) = 0;
int kfunc_def(security_change_sid)(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid) = 0;
int kfunc_def(security_sid_to_context)(u32 sid, char **scontext, u32 *scontext_len) = 0;
int kfunc_def(security_sid_to_context_force)(u32 sid, char **scontext, u32 *scontext_len) = 0;
int kfunc_def(security_sid_to_context_inval)(u32 sid, char **scontext, u32 *scontext_len) = 0;
int kfunc_def(security_context_to_sid)(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp) = 0;
int kfunc_def(security_context_str_to_sid)(const char *scontext, u32 *out_sid, gfp_t gfp) = 0;
int kfunc_def(security_context_to_sid_default)(const char *scontext, u32 scontext_len, u32 *out_sid, u32 def_sid,
                                               gfp_t gfp_flags) = 0;
int kfunc_def(security_context_to_sid_force)(const char *scontext, u32 scontext_len, u32 *sid) = 0;
int kfunc_def(security_get_user_sids)(u32 callsid, char *username, u32 **sids, u32 *nel) = 0;
int kfunc_def(security_port_sid)(u8 protocol, u16 port, u32 *out_sid) = 0;
int kfunc_def(security_ib_pkey_sid)(u64 subnet_prefix, u16 pkey_num, u32 *out_sid) = 0;
int kfunc_def(security_ib_endport_sid)(const char *dev_name, u8 port_num, u32 *out_sid) = 0;
int kfunc_def(security_netif_sid)(char *name, u32 *if_sid) = 0;
int kfunc_def(security_node_sid)(u16 domain, void *addr, u32 addrlen, u32 *out_sid) = 0;
int kfunc_def(security_validate_transition)(u32 oldsid, u32 newsid, u32 tasksid, u16 tclass) = 0;
int kfunc_def(security_validate_transition_user)(u32 oldsid, u32 newsid, u32 tasksid, u16 tclass) = 0;
int kfunc_def(security_bounded_transition)(u32 oldsid, u32 newsid) = 0;
int kfunc_def(security_sid_mls_copy)(u32 sid, u32 mls_sid, u32 *new_sid) = 0;
int kfunc_def(security_net_peersid_resolve)(u32 nlbl_sid, u32 nlbl_type, u32 xfrm_sid, u32 *peer_sid) = 0;
int kfunc_def(security_get_classes)(struct selinux_policy *policy, char ***classes, int *nclasses) = 0;
int kfunc_def(security_get_permissions)(struct selinux_policy *policy, char *class, char ***perms, int *nperms) = 0;
int kfunc_def(security_get_reject_unknown)(void) = 0;
int kfunc_def(security_get_allow_unknown)(void) = 0;

int kfunc_def(security_fs_use)(struct super_block *sb) = 0;
int kfunc_def(security_genfs_sid)(const char *fstype, const char *path, u16 sclass, u32 *sid) = 0;
int kfunc_def(selinux_policy_genfs_sid)(struct selinux_policy *policy, const char *fstype, const char *path, u16 sclass,
                                        u32 *sid) = 0;
int kfunc_def(security_netlbl_secattr_to_sid)(struct netlbl_lsm_secattr *secattr, u32 *sid) = 0;
int kfunc_def(security_netlbl_sid_to_secattr)(u32 sid, struct netlbl_lsm_secattr *secattr) = 0;
const char *kfunc_def(security_get_initial_sid_context)(u32 sid) = 0;

void kfunc_def(selinux_status_update_setenforce)(int enforcing) = 0;
void kfunc_def(selinux_status_update_policyload)(int seqno) = 0;
void kfunc_def(selinux_complete_init)(void) = 0;
void kfunc_def(exit_sel_fs)(void) = 0;
void kfunc_def(selnl_notify_setenforce)(int val) = 0;
void kfunc_def(selnl_notify_policyload)(u32 seqno) = 0;
int kfunc_def(selinux_nlmsg_lookup)(u16 sclass, u16 nlmsg_type, u32 *perm) = 0;

void kfunc_def(avtab_cache_init)(void) = 0;
void kfunc_def(ebitmap_cache_init)(void) = 0;
void kfunc_def(hashtab_cache_init)(void) = 0;
int kfunc_def(security_sidtab_hash_stats)(char *page) = 0;

void _linux_security_selinux_sym_match(const char *name, unsigned long addr)
{
    kvar_match(selinux_enabled_boot, name, addr);
    kvar_match(selinux_enabled, name, addr);
    kvar_match(selinux_state, name, addr);
    kvar_match(secclass_map, name, addr);

    kfunc_match(security_mls_enabled, name, addr);
    // kfunc_match(security_load_policy, name, addr);
    // kfunc_match(selinux_policy_commit, name, addr);
    // kfunc_match(selinux_policy_cancel, name, addr);
    // kfunc_match(security_read_policy, name, addr);
    // kfunc_match(security_read_state_kernel, name, addr);
    // kfunc_match(security_policycap_supported, name, addr);
    kfunc_match(security_compute_av, name, addr);
    kfunc_match(security_compute_xperms_decision, name, addr);
    kfunc_match(security_compute_av_user, name, addr);
    // kfunc_match(security_transition_sid, name, addr);
    // kfunc_match(security_transition_sid_user, name, addr);
    // kfunc_match(security_member_sid, name, addr);
    // kfunc_match(security_change_sid, name, addr);
    // kfunc_match(security_sid_to_context, name, addr);
    // kfunc_match(security_sid_to_context_force, name, addr);
    // kfunc_match(security_sid_to_context_inval, name, addr);
    // kfunc_match(security_context_to_sid, name, addr);
    // kfunc_match(security_context_str_to_sid, name, addr);
    // kfunc_match(security_context_to_sid_default, name, addr);
    // kfunc_match(security_context_to_sid_force, name, addr);
    // kfunc_match(security_get_user_sids, name, addr);
    // kfunc_match(security_port_sid, name, addr);
    // kfunc_match(security_ib_pkey_sid, name, addr);
    // kfunc_match(security_ib_endport_sid, name, addr);
    // kfunc_match(security_netif_sid, name, addr);
    // kfunc_match(security_node_sid, name, addr);
    // kfunc_match(security_validate_transition, name, addr);
    // kfunc_match(security_validate_transition_user, name, addr);
    // kfunc_match(security_bounded_transition, name, addr);
    // kfunc_match(security_sid_mls_copy, name, addr);
    // kfunc_match(security_net_peersid_resolve, name, addr);
    // kfunc_match(security_get_classes, name, addr);
    // kfunc_match(security_get_permissions, name, addr);
    // kfunc_match(security_get_reject_unknown, name, addr);
    // kfunc_match(security_get_allow_unknown, name, addr);

    // kfunc_match(security_fs_use, name, addr);
    // kfunc_match(security_genfs_sid, name, addr);
    // kfunc_match(selinux_policy_genfs_sid, name, addr);
    // kfunc_match(security_netlbl_secattr_to_sid, name, addr);
    // kfunc_match(security_netlbl_sid_to_secattr, name, addr);
    // kfunc_match(security_get_initial_sid_context, name, addr);

    // kfunc_match(selinux_status_update_setenforce, name, addr);
    // kfunc_match(selinux_status_update_policyload, name, addr);
    // kfunc_match(selinux_complete_init, name, addr);
    // kfunc_match(exit_sel_fs, name, addr);
    // kfunc_match(selnl_notify_setenforce, name, addr);
    // kfunc_match(selnl_notify_policyload, name, addr);
    // kfunc_match(selinux_nlmsg_lookup, name, addr);

    // kfunc_match(avtab_cache_init, name, addr);
    // kfunc_match(ebitmap_cache_init, name, addr);
    // kfunc_match(hashtab_cache_init, name, addr);
    // kfunc_match(security_sidtab_hash_stats, name, addr);
}