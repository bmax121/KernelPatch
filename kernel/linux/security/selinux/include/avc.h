#ifndef _SELINUX_AVC_H_
#define _SELINUX_AVC_H_

#include <ktypes.h>
#include <ksyms.h>
#include <security/selinux/include/security.h>

struct avc_entry;

struct task_struct;
struct inode;
struct sock;
struct sk_buff;
struct common_audit_data;
struct av_decision;

/*
 * We only need this data after we have decided to send an audit message.
 */
struct selinux_audit_data
{
    u32 ssid;
    u32 tsid;
    u16 tclass;
    u32 requested;
    u32 audited;
    u32 denied;
    int result;
    struct selinux_state *state;
};

struct avc_xperms_node
{
    struct extended_perms xp;
    struct list_head xpd_head; /* list head of extended_perms_decision */
};

struct avc_entry
{
    u32 ssid;
    u32 tsid;
    u16 tclass;
    struct av_decision avd;
    // kernel version >= 4.3.0, has avc_has_extended_perms method
    struct avc_xperms_node *xp_node;
};

struct avc_node
{
    struct avc_entry ae;
    struct hlist_node list; /* anchored in avc_cache->slots[i] */
    struct rcu_head rhead;
};

#define AVC_STRICT 1 /* Ignore permissive mode. */
#define AVC_EXTENDED_PERMS 2 /* update extended permissions */
#define AVC_NONBLOCKING 4 /* non blocking */

extern int kfunc_def(avc_denied)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u8 driver, u8 xperm, unsigned int flags,
                                 struct av_decision *avd);
extern int kfunc_def(slow_avc_audit)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                     u32 audited, u32 denied, int result, struct common_audit_data *a);

extern int kfunc_def(avc_has_perm_noaudit)(u32 ssid, u32 tsid, u16 tclass, u32 requested, unsigned flags,
                                           struct av_decision *avd);
extern int kfunc_def(avc_has_perm)(u32 ssid, u32 tsid, u16 tclass, u32 requested, struct common_audit_data *auditdata);
extern int kfunc_def(avc_has_perm_flags)(u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                         struct common_audit_data *auditdata, int flags);
extern int kfunc_def(avc_has_extended_perms)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u8 driver, u8 perm,
                                             struct common_audit_data *ad);

extern struct avc_node *kfunc_def(avc_lookup)(u32 ssid, u32 tsid, u16 tclass);
extern struct avc_node *kfunc_def(avc_compute_av)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd,
                                                  struct avc_xperms_node *xp_node);

#define kfunc_def_compat(func) kfunc_def(func##_compat)

typedef int kfunc_def_compat(avc_denied)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                         u8 driver, u8 xperm, unsigned int flags, struct av_decision *avd);
typedef int kfunc_def_compat(slow_avc_audit)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                             u32 audited, u32 denied, int result, struct common_audit_data *a);

typedef int kfunc_def_compat(avc_has_perm_noaudit)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
                                                   u32 requested, unsigned flags, struct av_decision *avd);
typedef int kfunc_def_compat(avc_has_perm)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                           struct common_audit_data *auditdata);
typedef int kfunc_def_compat(avc_has_perm_flags)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
                                                 u32 requested, struct common_audit_data *auditdata, int flags);
typedef int kfunc_def_compat(avc_has_extended_perms)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
                                                     u32 requested, u8 driver, u8 perm, struct common_audit_data *ad);

typedef struct avc_node *kfunc_def_compat(avc_lookup)(u32 ssid, u32 tsid, u16 tclass);
typedef struct avc_node *kfunc_def_compat(avc_compute_av)(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd,
                                                          struct avc_xperms_node *xp_node);

#endif