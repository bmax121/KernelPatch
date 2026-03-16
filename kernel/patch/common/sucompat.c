/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <linux/list.h>
#include <ktypes.h>
#include <compiler.h>
#include <stdbool.h>
#include <linux/syscall.h>
#include <ksyms.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <taskob.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <syscall.h>
#include <predata.h>
#include <kconfig.h>
#include <linux/vmalloc.h>
#include <sucompat.h>
#include <symbol.h>
#include <uapi/linux/limits.h>
#include <kstorage.h>

const char sh_path[] = SH_PATH;
const char default_su_path[] = SU_PATH;

#ifdef ANDROID
const char legacy_su_path[] = LEGACY_SU_PATH;
const char apd_path[] = APD_PATH;
#endif

static const char *current_su_path = 0;

static int su_kstorage_gid = -1;
static int exclude_kstorage_gid = -1;

#define SU_UID_FAST_MAX 32
static uid_t su_uid_fast_list[SU_UID_FAST_MAX];
static int su_uid_fast_count = 0;

static inline int is_su_uid_fast(uid_t uid)
{
    int count = READ_ONCE(su_uid_fast_count);
    for (int i = 0; i < count; i++) {
        if (READ_ONCE(su_uid_fast_list[i]) == uid) return 1;
    }
    return 0;
}

static void su_uid_fast_add(uid_t uid)
{
    int count = su_uid_fast_count;
    for (int i = 0; i < count; i++) {
        if (su_uid_fast_list[i] == uid) return;
    }
    if (count >= SU_UID_FAST_MAX) return;
    su_uid_fast_list[count] = uid;
    WRITE_ONCE(su_uid_fast_count, count + 1);
}

static void su_uid_fast_remove(uid_t uid)
{
    int count = su_uid_fast_count;
    for (int i = 0; i < count; i++) {
        if (su_uid_fast_list[i] == uid) {
            su_uid_fast_list[i] = su_uid_fast_list[count - 1];
            WRITE_ONCE(su_uid_fast_count, count - 1);
            return;
        }
    }
}

int is_su_allow_uid(uid_t uid)
{
    int rc = 0;
    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR_OR_NULL(ks) || ks->dlen <= 0) goto out;

    struct su_profile *profile = (struct su_profile *)ks->data;
    rc = profile->uid == uid;

out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(is_su_allow_uid);

int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext)
{
    if (!scontext) scontext = "";
    struct su_profile profile = {
        uid,
        to_uid,
    };
    memcpy(profile.scontext, scontext, SUPERCALL_SCONTEXT_LEN);
    int rc = write_kstorage(su_kstorage_gid, uid, &profile, 0, sizeof(struct su_profile), false);
    if (!rc) su_uid_fast_add(uid);
    logkfd("uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, scontext, rc);
    return rc;
}
KP_EXPORT_SYMBOL(su_add_allow_uid);

int su_remove_allow_uid(uid_t uid)
{
    su_uid_fast_remove(uid);
    return remove_kstorage(su_kstorage_gid, uid);
}
KP_EXPORT_SYMBOL(su_remove_allow_uid);

int su_allow_uid_nums()
{
    return kstorage_group_size(su_kstorage_gid);
}
KP_EXPORT_SYMBOL(su_allow_uid_nums);

static int allow_uids_cb(struct kstorage *kstorage, void *udata)
{
    struct
    {
        int is_user;
        uid_t *out_uids;
        int idx;
        int out_num;
    } *up = (typeof(up))udata;

    if (up->idx >= up->out_num) {
        return -ENOBUFS;
    }

    struct su_profile *profile = (struct su_profile *)kstorage->data;

    if (up->is_user) {
        int cprc = compat_copy_to_user(up->out_uids + up->idx, &profile->uid, sizeof(uid_t));
        if (cprc <= 0) {
            logkfd("compat_copy_to_user error: %d", cprc);
            return cprc;
        }
    } else {
        up->out_uids[up->idx] = profile->uid;
    }

    up->idx++;

    return 0;
}

int su_allow_uids(int is_user, uid_t *out_uids, int out_num)
{
    struct
    {
        int iu;
        uid_t *up;
        int idx;
        int out_num;
    } udata = { is_user, out_uids, 0, out_num };

    on_each_kstorage_elem(su_kstorage_gid, allow_uids_cb, &udata);

    return udata.idx;
}
KP_EXPORT_SYMBOL(su_allow_uids);

int su_allow_uid_profile(int is_user, uid_t uid, struct su_profile *out_profile)
{
    int rc = 0;

    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR(ks)) {
        rc = -ENOENT;
        goto out;
    }
    struct su_profile *profile = (struct su_profile *)ks->data;

    if (is_user) {
        rc = compat_copy_to_user(out_profile, profile, sizeof(struct su_profile));
        if (rc <= 0) {
            logkfd("compat_copy_to_user error: %d", rc);
            goto out;
        }
    } else {
        memcpy(out_profile, profile, sizeof(struct su_profile));
    }

out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(su_allow_uid_profile);

// no free, no lock
int su_reset_path(const char *path)
{
    if (!path) return -EINVAL;
    if (IS_ERR(path)) return PTR_ERR(path);
    current_su_path = path;
    logkfd("%s\n", current_su_path);
    dsb(ish);
    return 0;
}
KP_EXPORT_SYMBOL(su_reset_path);

const char *su_get_path()
{
    if (!current_su_path) current_su_path = default_su_path;
    return current_su_path;
}
KP_EXPORT_SYMBOL(su_get_path);

static void handle_before_execve(char **__user u_filename_p, char **__user uargv, void *udata)
{
    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        uid_t uid = current_uid();
        struct su_profile profile;
        if (su_allow_uid_profile(0, uid, &profile)) return;

        uid_t to_uid = profile.to_uid;
        const char *sctx = profile.scontext;
        commit_su(to_uid, sctx);

#ifdef ANDROID
        struct file *filp = filp_open(apd_path, O_RDONLY, 0);
        if (!filp || IS_ERR(filp)) {
#endif
            void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
            if (uptr && !IS_ERR(uptr)) {
                *u_filename_p = (char *__user)uptr;
            }
            logkfi("call su uid: %d, to_uid: %d, sctx: %s, uptr: %llx\n", uid, to_uid, sctx, uptr);
#ifdef ANDROID
        } else {
            filp_close(filp, 0);

            // command
            uint64_t sp = 0;
            sp = current_user_stack_pointer();
            sp -= sizeof(apd_path);
            sp &= 0xFFFFFFFFFFFFFFF8;
            int cplen = compat_copy_to_user((void *)sp, apd_path, sizeof(apd_path));
            if (cplen > 0) {
                *u_filename_p = (char *)sp;
            }

            // argv
            int argv_cplen = 0;
            if (strcmp(legacy_su_path, filename)) {
                if (argv_cplen <= 0) {
                    sp = sp ?: current_user_stack_pointer();
                    sp -= sizeof(legacy_su_path);
                    sp &= 0xFFFFFFFFFFFFFFF8;
                    argv_cplen = compat_copy_to_user((void *)sp, legacy_su_path, sizeof(legacy_su_path));
                    if (argv_cplen > 0) {
                        int rc = set_user_arg_ptr(0, *uargv, 0, sp);
                        if (rc < 0) { // todo: modify entire argv
                            logkfi("call apd argv error, uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, sctx,
                                   rc);
                        }
                    }
                }
            }
            logkfi("call apd uid: %d, to_uid: %d, sctx: %s, cplen: %d, %d\n", uid, to_uid, sctx, cplen, argv_cplen);
        }
#endif // ANDROID
    } else if (!strcmp(SUPERCMD, filename)) {
        void handle_supercmd(char **__user u_filename_p, char **__user uargv);
        handle_supercmd(u_filename_p, uargv);
        return;
    }
}

// Redirect su path to sh for faccessat/fstatat (makes su binary appear to exist)
static inline void su_redirect_path(struct user_pt_regs *regs)
{
    uid_t uid = current_uid();
    if (!is_su_uid_fast(uid)) return;

    char __user *ufilename = (char __user *)regs->regs[1];
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
        if (uptr && !IS_ERR(uptr))
            regs->regs[1] = (uint64_t)uptr;
    }
}

// el0_svc_common(struct pt_regs *regs, int scno, int sc_nr, syscall_fn_t *table)
// Single hook point for ALL syscalls — uniform trampoline overhead prevents
// timing side-channel detection regardless of baseline syscall choice.
static void before_svc_common(hook_fargs4_t *args, void *udata)
{
    struct user_pt_regs *regs = (struct user_pt_regs *)args->arg0;
    int scno = (int)args->arg1;

    switch (scno) {
    case __NR_execve:
    case 11: // compat32 execve
        handle_before_execve((char **)&regs->regs[0], (char **)&regs->regs[1], 0);
        break;
    case __NR_faccessat:
    case __NR3264_fstatat:
    case 334: // compat32 faccessat
    case 327: // compat32 fstatat64
        su_redirect_path(regs);
        break;
    }
}

int set_ap_mod_exclude(uid_t uid, int exclude)
{
    int rc = 0;
    if (exclude) {
        rc = write_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    } else {
        rc = remove_kstorage(exclude_kstorage_gid, uid);
    }
    return rc;
}
KP_EXPORT_SYMBOL(set_ap_mod_exclude);

int get_ap_mod_exclude(uid_t uid)
{
    int exclude = 0;
    int rc = read_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    if (rc < 0) return 0;
    return exclude;
}
KP_EXPORT_SYMBOL(get_ap_mod_exclude);

int list_ap_mod_exclude(uid_t *uids, int len)
{
    long ids[len];
    int cnt = list_kstorage_ids(exclude_kstorage_gid, ids, len, false);
    for (int i = 0; i < len; i++) {
        uids[i] = (uid_t)ids[i];
    }
    return cnt;
}
KP_EXPORT_SYMBOL(list_ap_mod_exclude);

int su_compat_init()
{
    current_su_path = default_su_path;

    su_kstorage_gid = try_alloc_kstroage_group();
    if (su_kstorage_gid != KSTORAGE_SU_LIST_GROUP) return -ENOMEM;

    exclude_kstorage_gid = try_alloc_kstroage_group();
    if (exclude_kstorage_gid != KSTORAGE_EXCLUDE_LIST_GROUP) return -ENOMEM;

#ifdef ANDROID
    // default shell
    if (!all_allow_sctx[0]) {
        strcpy(all_allow_sctx, ALL_ALLOW_SCONTEXT_MAGISK);
    }
    su_add_allow_uid(2000, 0, all_allow_sctx);
    su_add_allow_uid(0, 0, all_allow_sctx);
#endif

    hook_err_t rc = HOOK_NO_ERR;

    uint8_t su_config = patch_config->patch_su_config;
    bool enable = !!(su_config & PATCH_CONFIG_SU_ENABLE);
    bool wrap = !!(su_config & PATCH_CONFIG_SU_HOOK_NO_WRAP);
    log_boot("su config: %x, enable: %d, wrap: %d\n", su_config, enable, wrap);

    // if (!enable) return;

    // Single hook on el0_svc_common covers ALL syscalls (native + compat32)
    // with uniform trampoline overhead, preventing timing side-channel.
    // Requires -ffixed-x18 in CFLAGS to preserve shadow call stack.
    unsigned long svc_common = kallsyms_lookup_name("el0_svc_common.constprop.0");
    if (!svc_common) svc_common = kallsyms_lookup_name("el0_svc_common");
    if (svc_common) {
        rc = hook_wrap4((void *)svc_common, before_svc_common, 0, 0);
        log_boot("hook el0_svc_common(%lx) rc: %d\n", svc_common, rc);
    }

    return 0;
}