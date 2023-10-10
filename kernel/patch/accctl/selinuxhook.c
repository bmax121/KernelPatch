#include "accctl.h"

#include <hook.h>
#include <log.h>
#include <ksyms.h>
#include <taskext.h>
#include <linux/sched/task.h>
#include <asm/current.h>
#include <minc/string.h>
#include <security/selinux/include/avc.h>
#include <security/selinux/include/security.h>

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

#define HOOK_AVC_RET_ZERO_BEFORE()                   \
    struct task_ext *ext = get_current_task_ext();   \
    if (task_ext_valid(ext) && ext->selinux_allow) { \
        return 0;                                    \
    }
// #define HOOK_AVC_RET_ZERO_BEFORE()

#include <linux/printk.h>

int hook_backup(avc_has_perm_noaudit)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
                                      void *requested, void *flags, struct av_decision *avd) = 0;
int hook_replace(avc_has_perm_noaudit)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
                                       void *requested, void *flags, struct av_decision *avd)
{
    int rc = hook_call_backup(avc_has_perm_noaudit, state, ssid, tsid, tclass, requested, flags, avd);
    struct task_ext *ext = get_current_task_ext();
    if (task_ext_valid(ext) && ext->selinux_allow) {
        struct av_decision *avd = (struct av_decision *)avd;
        if (((uint64_t)state & 0xF000000000000000) != 0xF000000000000000) {
            avd = (struct av_decision *)flags;
        }
        if (((uint64_t)avd & 0xF000000000000000) == 0xF000000000000000) {
            avd->allowed = 0xffffffff;
            avd->auditallow = 0;
            avd->auditdeny = 0;
        }
        rc = 0;
    }
    return rc;
}

int hook_backup(avc_has_perm)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
                              struct common_audit_data *auditdata) = 0;
int hook_replace(avc_has_perm)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
                               struct common_audit_data *auditdata)
{
    HOOK_AVC_RET_ZERO_BEFORE();
    int rc = hook_call_backup(avc_has_perm, state, ssid, tsid, tclass, requested, auditdata);
    return rc;
}

int hook_backup(avc_has_perm_flags)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
                                    struct common_audit_data *auditdata, void *flags) = 0;
int hook_replace(avc_has_perm_flags)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
                                     struct common_audit_data *auditdata, void *flags)
{
    HOOK_AVC_RET_ZERO_BEFORE();
    int rc = hook_call_backup(avc_has_perm_flags, state, ssid, tsid, tclass, requested, auditdata, flags);
    return rc;
}

int hook_backup(avc_has_extended_perms)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
                                        void *requested, void *driver, void *perm, struct common_audit_data *ad);
int hook_replace(avc_has_extended_perms)(struct selinux_state *state, void *ssid, void *tsid, void *tclass,
                                         void *requested, void *driver, void *perm, struct common_audit_data *ad)
{
    HOOK_AVC_RET_ZERO_BEFORE();
    int rc = hook_call_backup(avc_has_extended_perms, state, ssid, tsid, tclass, requested, driver, perm, ad);
    return rc;
}

int hook_backup(avc_denied)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
                            void *driver, void *xperm, void *flags, struct av_decision *avd) = 0;

int hook_replace(avc_denied)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
                             void *driver, void *xperm, void *flags, struct av_decision *avd)
{
    HOOK_AVC_RET_ZERO_BEFORE();
    int rc = hook_call_backup(avc_denied, state, ssid, tsid, tclass, requested, driver, xperm, flags, avd);
    return rc;
}

void hook_backup(security_compute_av)(void *_state, void *_ssid, void *_tsid, void *_orig_tclass, void *_avd,
                                      void *_xperms) = 0;

// struct selinux_state *state, u32 ssid, u32 tsid, u16 orig_tclass, struct av_decision *avd, struct extended_perms *xperms
void hook_replace(security_compute_av)(void *_state, void *_ssid, void *_tsid, void *_orig_tclass, void *_avd,
                                       void *_xperms)
{
    hook_call_backup(security_compute_av, _state, _ssid, _tsid, _orig_tclass, _avd, _xperms);

    struct task_ext *ext = get_current_task_ext();
    if (task_ext_valid(ext) && ext->selinux_allow) {
        struct av_decision *avd = (struct av_decision *)_avd;
        struct extended_perms *xperms = (struct extended_perms *)_xperms;
        if ((uint64_t)_state <= 0xffffffffL) {
            avd = (struct av_decision *)_orig_tclass;
            xperms = (struct extended_perms *)_avd;
        }
        avd->allowed = 0xffffffff;
        avd->auditallow = 0;
        avd->auditdeny = 0;
        if (xperms) {
            min_memset(xperms->drivers.p, 0xff, sizeof(xperms->drivers.p));
        }
    }
}

void hook_backup(security_compute_xperms_decision)(void *_state, void *_ssid, void *_tsid, void *_orig_tclass,
                                                   void *_driver, void *_xpermd) = 0;

//struct selinux_state *state, u32 ssid, u32 tsid, u16 orig_tclass, u8 driver, struct extended_perms_decision *xpermd
void hook_replace(security_compute_xperms_decision)(void *_state, void *_ssid, void *_tsid, void *_orig_tclass,
                                                    void *_driver, void *_xpermd)
{
    hook_call_backup(security_compute_xperms_decision, _state, _ssid, _tsid, _orig_tclass, _driver, _xpermd);
    struct task_ext *ext = get_current_task_ext();
    if (task_ext_valid(ext) && ext->selinux_allow) {
        struct extended_perms_decision *xpermd = (struct extended_perms_decision *)_xpermd;
        if ((uint64_t)_state <= 0xffffffffL) {
            xpermd = (struct extended_perms_decision *)_driver;
        }
        min_memset(xpermd->allowed->p, 0xff, sizeof(xpermd->allowed->p));
        min_memset(xpermd->auditallow->p, 0, sizeof(xpermd->auditallow->p));
        min_memset(xpermd->dontaudit->p, 0xff, sizeof(xpermd->dontaudit->p));
    }
}

void hook_backup(security_compute_av_user)(void *_state, void *_ssid, void *_tsid, void *_tclass, void *_avd) = 0;

// struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd
void hook_replace(security_compute_av_user)(void *_state, void *_ssid, void *_tsid, void *_tclass, void *_avd)
{
    hook_call_backup(security_compute_av_user, _state, _ssid, _tsid, _tclass, _avd);

    struct task_ext *ext = get_current_task_ext();
    if (task_ext_valid(ext) && ext->selinux_allow) {
        struct av_decision *avd = (struct av_decision *)_avd;
        if ((uint64_t)_state <= 0xffffffffL) {
            avd = (struct av_decision *)_tclass;
        }
        avd->allowed = 0xffffffff;
        avd->auditallow = 0;
        avd->auditdeny = 0;
    }
}

int selinux_hook_install()
{
    hook_kfunc(avc_has_perm_noaudit);
    hook_kfunc(avc_has_perm);
    hook_kfunc(avc_has_perm_flags);
    hook_kfunc(avc_has_extended_perms);
    // hook_kfunc(avc_denied);

    hook_kfunc(security_compute_av);
    hook_kfunc(security_compute_xperms_decision);
    hook_kfunc(security_compute_av_user);
    return 0;
}