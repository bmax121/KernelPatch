/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "accctl.h"

#include <hook.h>
#include <log.h>
#include <ksyms.h>
#include <taskext.h>
#include <linux/sched/task.h>
#include <asm/current.h>
#include <security/selinux/include/avc.h>
#include <security/selinux/include/security.h>
#include <predata.h>

#define SHOW_AVC_PASS_LOG

#if 0
static void _selinux_debug(u32 ssid, u32 tsid, u16 tclass, u32 requested)
{
    logkfd("ssid: %x, tsid: %x, tclass: %x, requested: %x\n", ssid, tsid, tclass, requested);
    char *scontext = 0;
    u32 sctx_len = 0;
    char *tcontext = 0;
    u32 tctx_len = 0;
    security_sid_to_context(ssid, &scontext, &sctx_len);
    security_sid_to_context(tsid, &tcontext, &tctx_len);
    const char *stclass = kvar_val(secclass_map)[tclass - 1].name;
    const char *const *perms = kvar_val(secclass_map)[tclass - 1].perms;
    char buf[128] = { '\0' };
    for (int i = 0; i < (sizeof(u32) * 8); i++) {
        if ((1 << i) & requested) {
            int len = min_strlen(buf);
            min_snprintf(buf + len, 128 - len, "%s ", perms[i]);
        }
    }
    logkfd("context: %s, tcontext: %s, tclass: %s, perms: %s\n", scontext, tcontext, stclass, buf);
}
#endif

#define hook_backup(func) (*backup_##func)
#define hook_replace(func) replace_##func
#define hook_call_backup(func, ...) backup_##func(__VA_ARGS__)

#define hook_kfunc_with(func, replace, backup)                                                                 \
    if (kfunc(func)) {                                                                                         \
        hook_err_t err_##func = hook(kfunc(func), replace, (void **)&backup);                                  \
        if (err_##func != HOOK_NO_ERR) log_boot("hook %s, %llx, error: %d\n", #func, kfunc(func), err_##func); \
    } else {                                                                                                   \
        log_boot("no symbol: %s\n", #func);                                                                    \
    }

#define hook_kfunc(func) hook_kfunc_with(func, replace_##func, backup_##func)

#define find_and_hook_func_with(func, replace, backup)                                                         \
    unsigned long addr = kallsyms_lookup_name(#func);                                                          \
    if (addr) {                                                                                                \
        hook_err_t err_##func = hook(addr, replace, (void **)&backup);                                         \
        if (err_##func != HOOK_NO_ERR) log_boot("hook %s, %llx, error: %d\n", #func, kfunc(func), err_##func); \
    } else {                                                                                                   \
        log_boot("no symbol %s\n", #func);                                                                     \
    }

#define HOOK_AVC_RET_ZERO_BEFORE()                                                          \
    struct task_ext *ext = get_current_task_ext();                                          \
    if (unlikely(task_ext_valid(ext) && (ext->selinux_allow || ext->priv_selinux_allow))) { \
        return 0;                                                                           \
    }

static int (*avc_denied_backup)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
                                void *driver, void *xperm, void *flags, struct av_decision *avd) = 0;

static int avc_denied_replace(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass, void *_requested,
                              void *_driver, void *_xperm, void *_flags, struct av_decision *_avd)
{
    struct task_ext *ext = get_current_task_ext();
    if (unlikely(task_ext_valid(ext) && (ext->selinux_allow || ext->priv_selinux_allow))) {
        struct av_decision *avd = (struct av_decision *)_avd;
        if ((uint64_t)_state <= 0xffffffffL) {
            avd = (struct av_decision *)_flags;
        }
        avd->allowed = 0xffffffff;
        avd->auditallow = 0;
        avd->auditdeny = 0;
        return 0;
    }
    int rc = avc_denied_backup(_state, _ssid, _tsid, _tclass, _requested, _driver, _xperm, _flags, _avd);
    return rc;
}

static int (*slow_avc_audit_backup)(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass,
                                    void *_requested, void *_audited, void *_denied, void *_result,
                                    struct common_audit_data *_a) = 0;

static int slow_avc_audit_replace(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass,
                                  void *_requested, void *_audited, void *_denied, void *_result,
                                  struct common_audit_data *_a)
{
    struct task_ext *ext = get_current_task_ext();
    if (unlikely(task_ext_valid(ext) && (ext->selinux_allow || ext->priv_selinux_allow))) {
        return 0;
    }
    int rc = slow_avc_audit_backup(_state, _ssid, _tsid, _tclass, _requested, _audited, _denied, _result, _a);
    return rc;
}

// static inline void *min_memset(void *dst, int c, size_t n)
// {
//     char *q = dst;
//     while (n--) {
//         *q++ = c;
//     }
//     return dst;
// }

// static int hook_backup(avc_has_perm_noaudit)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
//                                              void *requested, void *flags, struct av_decision *avd) = 0;
// static int hook_replace(avc_has_perm_noaudit)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
//                                               void *requested, void *flags, struct av_decision *avd)
// {
//     // HOOK_AVC_RET_ZERO_BEFORE();

//     struct task_ext *ext = get_current_task_ext();
//     if (unlikely(task_ext_valid(ext) && (ext->selinux_allow || ext->priv_selinux_allow))) {
//         struct av_decision *avd = (struct av_decision *)avd;
//         if (((uint64_t)state & 0xF000000000000000) != 0xF000000000000000) {
//             avd = (struct av_decision *)flags;
//         }
//         if (((uint64_t)avd & 0xF000000000000000) == 0xF000000000000000) {
//             avd->allowed = 0xffffffff;
//             avd->auditallow = 0;
//             avd->auditdeny = 0;
//         }
//         return 0;
//     }

//     int rc = hook_call_backup(avc_has_perm_noaudit, state, ssid, tsid, tclass, requested, flags, avd);

//     return rc;
// }

// static int hook_backup(avc_has_perm)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
//                                      struct common_audit_data *auditdata) = 0;
// static int hook_replace(avc_has_perm)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
//                                       void *requested, struct common_audit_data *auditdata)
// {
//     HOOK_AVC_RET_ZERO_BEFORE();
//     int rc = hook_call_backup(avc_has_perm, state, ssid, tsid, tclass, requested, auditdata);
//     return rc;
// }

// static int hook_backup(avc_has_perm_flags)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
//                                            void *requested, struct common_audit_data *auditdata, void *flags) = 0;
// static int hook_replace(avc_has_perm_flags)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
//                                             void *requested, struct common_audit_data *auditdata, void *flags)
// {
//     HOOK_AVC_RET_ZERO_BEFORE();
//     int rc = hook_call_backup(avc_has_perm_flags, state, ssid, tsid, tclass, requested, auditdata, flags);
//     return rc;
// }

// // int avc_has_extended_perms((struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u8 driver, u8 xperm, struct common_audit_data *ad)
// static int hook_backup(avc_has_extended_perms)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
//                                                void *requested, void *driver, void *perm, struct common_audit_data *ad);
// static int hook_replace(avc_has_extended_perms)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
//                                                 void *requested, void *driver, void *perm, struct common_audit_data *ad)
// {
//     HOOK_AVC_RET_ZERO_BEFORE();
//     int rc = hook_call_backup(avc_has_extended_perms, state, ssid, tsid, tclass, requested, driver, perm, ad);
//     return rc;
// }

// static void make_avc_node_all_perm(struct avc_node *node)
// {
//     struct avc_entry *ae = &node->ae;
//     struct av_decision *avd = &ae->avd;
//     avd->allowed = 0xffffffff;
//     avd->auditallow = 0;
//     avd->auditdeny = 0;
//     if (likely(kfunc(avc_has_extended_perms))) {
//         struct avc_xperms_node *xp_node = ae->xp_node;
//         if (xp_node) {
//             struct extended_perms *xp = &xp_node->xp;
//             min_memset(xp->drivers.p, 0xff, sizeof(xp->drivers.p));
//         }
//     }
// }

// struct avc_node *hook_backup(avc_lookup)(void *_state, void *_ssid, void *_tsid, void *_tclass) = 0;

// // struct selinux_avc *avc, u32 ssid, u32 tsid, u16 tclass
// struct avc_node *hook_replace(avc_lookup)(void *_state, void *_ssid, void *_tsid, void *_tclass)
// {
//     struct avc_node *node = hook_call_backup(avc_lookup, _state, _ssid, _tsid, _tclass);
//     if (!node) return node;

//     struct task_ext *ext = get_current_task_ext();
//     if (unlikely(task_ext_valid(ext) && (ext->selinux_allow || ext->priv_selinux_allow))) {
//         make_avc_node_all_perm(node);
//     }
//     return node;
// }

// struct avc_node *hook_backup(avc_compute_av)(void *_state, void *_ssid, void *_tsid, void *_tclass, void *_avd,
//                                              void *_xp_node);

// // struct selinux_state *state,u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd, struct avc_xperms_node *xp_node
// struct avc_node *hook_replace(avc_compute_av)(void *_state, void *_ssid, void *_tsid, void *_tclass, void *_avd,
//                                               void *_xp_node)
// {
//     struct avc_node *node = hook_call_backup(avc_compute_av, _state, _ssid, _tsid, _tclass, _avd, _xp_node);
//     struct task_ext *ext = get_current_task_ext();
//     if (unlikely(task_ext_valid(ext) && (ext->selinux_allow || ext->priv_selinux_allow))) {
//         struct av_decision *avd = (struct av_decision *)_avd;
//         struct avc_xperms_node *xp_node = (struct avc_xperms_node *)_xp_node;
//         if ((uint64_t)_state <= 0xffffffffL) {
//             avd = (struct av_decision *)_tclass;
//             xp_node = (struct avc_xperms_node *)_avd;
//         }
//         avd->allowed = 0xffffffff;
//         avd->auditallow = 0;
//         avd->auditdeny = 0;
//         if (xp_node) {
//             struct extended_perms *xp = &xp_node->xp;
//             min_memset(xp->drivers.p, 0xff, sizeof(xp->drivers.p));
//         }
//         make_avc_node_all_perm(node);
//     }
//     return node;
// }

// static void hook_backup(security_compute_av)(void *_state, void *_ssid, void *_tsid, void *_orig_tclass, void *_avd,
//                                              void *_xperms) = 0;

// // struct selinux_state *state, u32 ssid, u32 tsid, u16 orig_tclass, struct av_decision *avd, struct extended_perms *xperms
// static void hook_replace(security_compute_av)(void *_state, void *_ssid, void *_tsid, void *_orig_tclass, void *_avd,
//                                               void *_xperms)
// {
//     hook_call_backup(security_compute_av, _state, _ssid, _tsid, _orig_tclass, _avd, _xperms);

//     struct task_ext *ext = get_current_task_ext();
//     if (unlikely(task_ext_valid(ext) && (ext->selinux_allow || ext->priv_selinux_allow))) {
//         struct av_decision *avd = (struct av_decision *)_avd;
//         struct extended_perms *xperms = (struct extended_perms *)_xperms;
//         if ((uint64_t)_state <= 0xffffffffL) {
//             avd = (struct av_decision *)_orig_tclass;
//             xperms = (struct extended_perms *)_avd;
//         }
//         avd->allowed = 0xffffffff;
//         avd->auditallow = 0;
//         avd->auditdeny = 0;
//         if (xperms) {
//             min_memset(xperms->drivers.p, 0xff, sizeof(xperms->drivers.p));
//         }
//     }
// }

// static void hook_backup(security_compute_xperms_decision)(void *_state, void *_ssid, void *_tsid, void *_orig_tclass,
//                                                           void *_driver, void *_xpermd) = 0;

// //struct selinux_state *state, u32 ssid, u32 tsid, u16 orig_tclass, u8 driver, struct extended_perms_decision *xpermd
// static void hook_replace(security_compute_xperms_decision)(void *_state, void *_ssid, void *_tsid, void *_orig_tclass,
//                                                            void *_driver, void *_xpermd)
// {
//     hook_call_backup(security_compute_xperms_decision, _state, _ssid, _tsid, _orig_tclass, _driver, _xpermd);
//     struct task_ext *ext = get_current_task_ext();
//     if (unlikely(task_ext_valid(ext) && (ext->selinux_allow || ext->priv_selinux_allow))) {
//         struct extended_perms_decision *xpermd = (struct extended_perms_decision *)_xpermd;
//         if ((uint64_t)_state <= 0xffffffffL) {
//             xpermd = (struct extended_perms_decision *)_driver;
//         }
//         min_memset(xpermd->allowed->p, 0xff, sizeof(xpermd->allowed->p));
//         min_memset(xpermd->auditallow->p, 0, sizeof(xpermd->auditallow->p));
//         min_memset(xpermd->dontaudit->p, 0xff, sizeof(xpermd->dontaudit->p));
//     }
// }

// static void hook_backup(security_compute_av_user)(void *_state, void *_ssid, void *_tsid, void *_tclass,
//                                                   void *_avd) = 0;

// // struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd
// static void hook_replace(security_compute_av_user)(void *_state, void *_ssid, void *_tsid, void *_tclass, void *_avd)
// {
//     hook_call_backup(security_compute_av_user, _state, _ssid, _tsid, _tclass, _avd);

//     struct task_ext *ext = get_current_task_ext();
//     if (unlikely(task_ext_valid(ext) && (ext->selinux_allow || ext->priv_selinux_allow))) {
//         struct av_decision *avd = (struct av_decision *)_avd;
//         if ((uint64_t)_state <= 0xffffffffL) {
//             avd = (struct av_decision *)_tclass;
//         }
//         avd->allowed = 0xffffffff;
//         avd->auditallow = 0;
//         avd->auditdeny = 0;
//     }
// }

int selinux_hook_install()
{
    unsigned long avc_denied_addr = get_preset_patch_sym()->avc_denied;
    if (avc_denied_addr) {
        hook_err_t err = hook((void *)avc_denied_addr, (void *)avc_denied_replace, (void **)&avc_denied_backup);
        if (err != HOOK_NO_ERR) {
            log_boot("hook avc_denied_addr: %llx, error: %d\n", avc_denied_addr, err);
        }
    }

    unsigned long slow_avc_audit_addr = get_preset_patch_sym()->slow_avc_audit;
    if (slow_avc_audit_addr) {
        hook_err_t err =
            hook((void *)slow_avc_audit_addr, (void *)slow_avc_audit_replace, (void **)&slow_avc_audit_backup);
        if (err != HOOK_NO_ERR) {
            log_boot("hook slow_avc_audit: %llx, error: %d\n", slow_avc_audit_addr, err);
        }
    }

    // hook_kfunc(avc_denied);
    // hook_kfunc(slow_avc_audit);

    // hook_kfunc(avc_has_perm_noaudit);
    // hook_kfunc(avc_has_perm);
    // hook_kfunc(avc_has_perm_flags);
    // hook_kfunc(avc_has_extended_perms);

    // we can't hook avc_compute_av and ..., it will 'avc_update_node' with diffused permission allowed
    // hook_kfunc(avc_lookup);
    // hook_kfunc(avc_compute_av);

    // hook_kfunc(security_compute_av);
    // hook_kfunc(security_compute_xperms_decision);
    // hook_kfunc(security_compute_av_user);

    return 0;
}