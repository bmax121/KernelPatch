#include "accctl.h"

#include <hook.h>
#include <log.h>

#include <init/ksyms.h>
#include <security/include/avc.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <asm/current.h>
#include "taskext.h"

int hook_backup(avc_has_perm_noaudit)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                      unsigned flags, struct av_decision *avd) = 0;
int hook_backup(avc_has_perm)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                              struct common_audit_data *auditdata) = 0;
int hook_backup(avc_has_perm_flags)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                    struct common_audit_data *auditdata, int flags) = 0;
int hook_backup(avc_has_extended_perms)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                        u8 driver, u8 perm, struct common_audit_data *ad) = 0;

#define SHOW_AVC_PASS_LOG

int hook_replace(avc_has_perm_noaudit)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                       unsigned flags, struct av_decision *avd)
{
    int ret = hook_call_backup(avc_has_perm_noaudit, state, ssid, tsid, tclass, requested, flags, avd);
    struct task_struct *task = current;
    // if (!is_white_task(task)) return ret;
    struct task_ext *ext = get_task_ext(task);
    if (!task_ext_valid(ext) || ext->selinux_perm != EXT_SELINUX_PERM_ALL) return ret;
#ifdef SHOW_AVC_PASS_LOG
    if (ret) {
        struct pid *spid = get_task_pid(task, PIDTYPE_PID);
        pid_t pid = pid_vnr(spid);
        put_pid(spid);
        logkd("avc_has_perm_noaudit pass pid: %d, avc: %d\n", pid, ret);
    }
#endif
    ret = 0;
    return ret;
}

int hook_replace(avc_has_perm)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                               struct common_audit_data *auditdata)
{
    int ret = hook_call_backup(avc_has_perm, state, ssid, tsid, tclass, requested, auditdata);
    struct task_struct *task = current;
    // if (!is_white_task(task)) return ret;
    struct task_ext *ext = get_task_ext(task);
    if (!task_ext_valid(ext) || ext->selinux_perm != EXT_SELINUX_PERM_ALL) return ret;
#ifdef SHOW_AVC_PASS_LOG
    if (ret) {
        struct pid *spid = get_task_pid(task, PIDTYPE_PID);
        pid_t pid = pid_vnr(spid);
        put_pid(spid);
        logkd("avc_has_perm pass pid: %d, avc: %d\n", pid, ret);
    }
#endif
    ret = 0;
    return ret;
}

int hook_replace(avc_has_perm_flags)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                     struct common_audit_data *auditdata, int flags)
{
    int ret = hook_call_backup(avc_has_perm_flags, state, ssid, tsid, tclass, requested, auditdata, flags);
    struct task_struct *task = current;
    // if (!is_white_task(task)) return ret;
    struct task_ext *ext = get_task_ext(task);
    if (!task_ext_valid(ext) || ext->selinux_perm != EXT_SELINUX_PERM_ALL) return ret;
#ifdef SHOW_AVC_PASS_LOG
    if (ret) {
        struct pid *spid = get_task_pid(task, PIDTYPE_PID);
        pid_t pid = pid_vnr(spid);
        put_pid(spid);
        logkd("avc_has_perm_flags pass pid: %d, avc: %d\n", pid, ret);
    }
#endif
    ret = 0;
    return ret;
}

int hook_replace(avc_has_extended_perms)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                         u8 driver, u8 perm, struct common_audit_data *ad)
{
    int ret = hook_call_backup(avc_has_extended_perms, state, ssid, tsid, tclass, requested, driver, perm, ad);
    struct task_struct *task = current;
    // if (!is_white_task(task)) return ret;
    struct task_ext *ext = get_task_ext(task);
    if (!task_ext_valid(ext) || ext->selinux_perm != EXT_SELINUX_PERM_ALL) return ret;
#ifdef SHOW_AVC_PASS_LOG
    if (ret) {
        struct pid *spid = get_task_pid(task, PIDTYPE_PID);
        pid_t pid = pid_vnr(spid);
        put_pid(spid);
        logkd("avc_has_extended_perms pass pid: %d, avc: %d\n", pid, ret);
    }
#endif
    ret = 0;
    return ret;
}

int selinux_hook_install()
{
    hook_kfunc(avc_has_perm_noaudit);
    hook_kfunc(avc_has_perm);
    hook_kfunc(avc_has_perm_flags);
    hook_kfunc(avc_has_extended_perms);
    return 0;
}