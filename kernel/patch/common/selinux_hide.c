/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Built-in selinux_hide feature, 
 * 
 *
 * The kernel is driven by the post-fs-data before/after events reported via
 * 
 * keys off: "post-fs-data"/"before" installs the hooks (and honors the
 * /data/adb/ap/selinux_hide control file), "after" is the finalize point.
 *
 * Supported only on kernels >= 4.19; below that even a forced enable is a
 * no-op (see selinux_hide_control / selinux_hide_enable).
 *
 * On the 4.19..6.3 range the context/access/setprocattr hooks answer against a
 * 
 * deep copied at post-fs-data "before" while the live policy is still untouched, so
 * a root app sees the pre-modification policy.  Apps (uid >= 10000) also see a
 * fake /sys/fs/selinux/status (enforcing=1, clean seqno), hiding permissive /
 * disabled SELinux and policy reloads.  Outside that range only the status
 * hide is active.
 */

#include <selinux_hide.h>
#include <selinux_sepolicy.h>

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>
#include <predata.h>
#include <kputils.h>
#include <baselib.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include <security/selinux/include/security.h>
#include <security/selinux/include/avc.h>

/* ---- feature constants ---- */
#ifdef ANDROID
extern int android_is_safe_mode;
#endif

#define KP_SELINUX_HIDE_FILE "/data/adb/ap/selinux_hide"
#define KP_SELINUX_HIDE_MIN_VERSION VERSION(4, 19, 0)

#define KP_O_RDONLY 0
#define KP_PAGE_SIZE 4096
#define KP_SIMPLE_TRANSACTION_LIMIT 4096
#define KP_GFP_KERNEL 0xcc0u /* __GFP_RECLAIM | __GFP_IO | __GFP_FS */

/* SELinux class / permission constants, matching
 * security/selinux/include/classmap.h (class numbers are 1-based indices). */
#define KP_SECCLASS_SECURITY 1
#define KP_SECCLASS_PROCESS 2
#define KP_SECINITSID_SECURITY 2 /* initial SIDs: kernel=1, security=2 */
#define KP_SECURITY__COMPUTE_AV (1U << 0)
#define KP_SECURITY__CHECK_CONTEXT (1U << 3)
#define KP_PROCESS__SETCURRENT (1U << 24)

/* struct selinux_kernel_status (20 bytes) */
#define KP_SELINUX_KERNEL_STATUS_VERSION 1
#define KP_SELINUX_STATUS_SIZE 20

/* ---- state ---- */

static bool selinux_hide_enabled;

typedef void (*security_cred_getsecid_fn)(const struct cred *c, u32 *secid);
static security_cred_getsecid_fn kp_security_cred_getsecid;

typedef ssize_t (*sel_write_op_fn)(struct file *, char *, size_t);
typedef int (*sel_mmap_status_fn)(struct file *, struct vm_area_struct *);
typedef ssize_t (*sel_read_status_fn)(struct file *, char __user *, size_t, loff_t *);
typedef int (*selinux_setprocattr_fn)(const char *, void *, size_t);

static unsigned long sel_write_context_addr;
static unsigned long sel_write_access_addr;
static unsigned long sel_read_handle_status_addr;
static unsigned long sel_mmap_handle_status_addr;
static unsigned long selinux_setprocattr_addr;

static sel_write_op_fn orig_context_write;
static sel_write_op_fn orig_access_write;
static selinux_setprocattr_fn orig_setprocattr;
static sel_read_status_fn orig_sel_read_handle_status;
static sel_mmap_status_fn orig_sel_mmap_handle_status;

static unsigned char fake_status_bytes[KP_SELINUX_STATUS_SIZE];
static void *fake_status_vaddr; /* vmalloc'd page mapped for uid >= 10000 */

static unsigned long g_hooked[8];
static int g_hooked_cnt;

static bool selinux_hide_is_supported(void)
{
    return kver >= KP_SELINUX_HIDE_MIN_VERSION;
}

/* ---- helpers ---- */

static void put_u32_le(unsigned char *dst, u32 value)
{
    dst[0] = (unsigned char)(value & 0xff);
    dst[1] = (unsigned char)((value >> 8) & 0xff);
    dst[2] = (unsigned char)((value >> 16) & 0xff);
    dst[3] = (unsigned char)((value >> 24) & 0xff);
}

/*
 * Values a clean, enforcing device is expected to expose in
 * /sys/fs/selinux/status.  On modern kernels a policy reload bumps policyload
 * and the sequence is nonzero; older kernels stay at the boot-time 0/0.
 */
static void fill_fake_status_bytes(void)
{
    u32 seq, pload;

    if (kver >= VERSION(6, 7, 0)) {
        seq = 4;
        pload = 1;
    } else {
        seq = 0;
        pload = 0;
    }
    /* access-query responses report the same seqno (selinux_sepolicy_clean_seq). */
    seq = selinux_sepolicy_clean_seq();

    lib_memset(fake_status_bytes, 0, sizeof(fake_status_bytes));
    put_u32_le(fake_status_bytes + 0, KP_SELINUX_KERNEL_STATUS_VERSION);
    put_u32_le(fake_status_bytes + 4, seq);
    put_u32_le(fake_status_bytes + 8, 1);  /* enforcing -- always report enforcing */
    put_u32_le(fake_status_bytes + 12, pload);
    put_u32_le(fake_status_bytes + 16, 1); /* deny_unknown */
}

static void init_fake_status(void)
{
    if (fake_status_vaddr) return;
    void *p = kp_vmalloc(KP_PAGE_SIZE);
    if (!p) {
        logkfw("selinux_hide: vmalloc unavailable, fake status disabled\n");
        return;
    }
    lib_memcpy(p, fake_status_bytes, sizeof(fake_status_bytes));
    fake_status_vaddr = p;
    logkfi("selinux_hide: fake status page ready (%x)\n", kver);
}

/* Caller's SID via the LSM cred->getsecid hook; 0 means "could not determine". */
static u32 kp_current_sid(void)
{
    const struct cred *cred;

    if (!kp_security_cred_getsecid || task_struct_offset.cred_offset < 0) return 0;
    cred = *(const struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    if (!cred) return 0;
    u32 sid = 0;
    kp_security_cred_getsecid(cred, &sid);
    return sid;
}

/* avc_has_perm with the 4.17..6.3 state-prepended signature handled. */
static int kp_avc_has_perm(u32 ssid, u32 tsid, u16 tclass, u32 requested, struct common_audit_data *auditdata)
{
    if (!kfunc(avc_has_perm) || !selinux_has_selinux_state()) return -ENOSYS;

    if (selinux_need_call_compat()) {
        typedef int (*avc_has_perm_compat_t)(struct selinux_state *, u32, u32, u16, u32,
                                             struct common_audit_data *);
        return ((avc_has_perm_compat_t)kfunc(avc_has_perm))(kvar(selinux_state), ssid, tsid, tclass, requested,
                                                            auditdata);
    }
    return kfunc(avc_has_perm)(ssid, tsid, tclass, requested, auditdata);
}

/* ---- /sys/fs/selinux/context handler ---- */

static ssize_t my_write_context(struct file *file, char *buf, size_t size)
{
    if (likely(current_uid() < 10000)) {
        return orig_context_write(file, buf, size);
    }
    if (!kfunc(security_context_to_sid) || !kfunc(security_sid_to_context) || !kfunc(avc_has_perm) ||
        !selinux_has_selinux_state()) {
        return orig_context_write(file, buf, size);
    }

    char *canon = NULL;
    u32 sid, len;
    ssize_t length;
    u32 csid = kp_current_sid();
    bool use_backup = selinux_sepolicy_backup_ready();

    if (!csid) return orig_context_write(file, buf, size); /* cannot gate -> stock */

    length = kp_avc_has_perm(csid, KP_SECINITSID_SECURITY, KP_SECCLASS_SECURITY, KP_SECURITY__CHECK_CONTEXT, NULL);
    if (length) goto out;

    /* The backup answers authoritatively when ready: contexts a clean policy
     * lacks (e.g. magisk/ksu) must NOT fall back to the live policy, or the
     * hide is undone. */
    if (use_backup)
        length = selinux_sepolicy_context_to_sid(buf, size, &sid, KP_GFP_KERNEL);
    else
        length = security_context_to_sid(buf, size, &sid, KP_GFP_KERNEL);
    if (length) goto out;

    if (use_backup)
        length = selinux_sepolicy_sid_to_context(sid, &canon, &len);
    else
        length = security_sid_to_context(sid, &canon, &len);
    if (length) goto out;

    length = -ERANGE;
    if (len > KP_SIMPLE_TRANSACTION_LIMIT) {
        logkfw("SELinux: %s:  context size (%u) exceeds payload max\n", __func__, len);
        goto out;
    }

    lib_memcpy(buf, canon, len);
    length = len;
out:
    kfree(canon);
    return length;
}

/* ---- /sys/fs/selinux/access handler ---- */

static ssize_t my_write_access(struct file *file, char *buf, size_t size)
{
    if (likely(current_uid() < 10000)) {
        return orig_access_write(file, buf, size);
    }
    if (!kfunc(security_context_str_to_sid) || !kfunc(security_compute_av_user) || !kfunc(avc_has_perm) ||
        !selinux_has_selinux_state()) {
        return orig_access_write(file, buf, size);
    }

    char *scon = NULL, *tcon = NULL, *tmp = NULL;
    u32 ssid, tsid;
    u16 tclass;
    struct av_decision avd;
    ssize_t length;
    u32 csid = kp_current_sid();
    bool use_backup = selinux_sepolicy_backup_ready();

    if (!csid) return orig_access_write(file, buf, size); /* cannot gate -> stock */

    length = kp_avc_has_perm(csid, KP_SECINITSID_SECURITY, KP_SECCLASS_SECURITY, KP_SECURITY__COMPUTE_AV, NULL);
    if (length) goto out;

    length = -ENOMEM;
    scon = kp_vmalloc(size + 1);
    if (!scon) goto out;
    tcon = kp_vmalloc(size + 1);
    if (!tcon) goto out;
    tmp = kp_vmalloc(size + 1);
    if (!tmp) goto out;

    lib_memcpy(tmp, buf, size);
    tmp[size] = '\0';

    length = -EINVAL;
    if (sscanf(tmp, "%s %s %hu", scon, tcon, &tclass) != 3) goto out;

    if (use_backup)
        length = selinux_sepolicy_context_str_to_sid(scon, &ssid, KP_GFP_KERNEL);
    else
        length = security_context_str_to_sid(scon, &ssid, KP_GFP_KERNEL);
    if (length) goto out;

    if (use_backup)
        length = selinux_sepolicy_context_str_to_sid(tcon, &tsid, KP_GFP_KERNEL);
    else
        length = security_context_str_to_sid(tcon, &tsid, KP_GFP_KERNEL);
    if (length) goto out;

    if (use_backup)
        selinux_sepolicy_compute_av_user(ssid, tsid, tclass, &avd);
    else
        security_compute_av_user(ssid, tsid, tclass, &avd);

    length = scnprintf(buf, KP_SIMPLE_TRANSACTION_LIMIT, "%x %x %x %x %u %x", avd.allowed, 0xffffffff,
                       avd.auditallow, avd.auditdeny, avd.seqno, avd.flags);
out:
    kp_vfree(tmp);
    kp_vfree(tcon);
    kp_vfree(scon);
    return length;
}

/* ---- setprocattr handler ---- */

static int my_setprocattr(const char *name, void *value, size_t size)
{
    int error;
    u32 mysid;
    char *str = value;
    bool use_backup = selinux_sepolicy_backup_ready();

    if (likely(current_uid() < 10000)) goto call_orig;
    if (lib_strcmp(name, "current")) goto call_orig;
    if (!kfunc(avc_has_perm) || !selinux_has_selinux_state()) goto call_orig;

    mysid = kp_current_sid();
    if (!mysid) goto call_orig;

    error = kp_avc_has_perm(mysid, mysid, KP_SECCLASS_PROCESS, KP_PROCESS__SETCURRENT, NULL);
    if (error) goto call_orig; /* let the stock handler decide (it does the same check) */

    /* Advisory pre-validation against the clean snapshot: only ever adds
     * acceptance; never reject here -- the stock handler re-checks against the
     * live policy, and rejecting (e.g. for a forked app's context) breaks boot. */
    if (use_backup && size && str[0] && str[0] != '\n') {
        char *copy = kp_vmalloc(size + 1);
        if (copy) {
            u32 n = size;
            u32 vsid = 0;
            lib_memcpy(copy, str, size);
            copy[size] = '\0';
            if (copy[n - 1] == '\n') copy[n - 1] = '\0';
            selinux_sepolicy_context_to_sid(copy, n, &vsid, KP_GFP_KERNEL);
            kp_vfree(copy);
        }
    }
call_orig:
    return orig_setprocattr(name, value, size);
}

/* ---- /sys/fs/selinux/status (read + mmap) ---- */

static ssize_t my_sel_read_handle_status(struct file *filp, char __user *buffer, size_t count, loff_t *ppos)
{
    if (selinux_hide_enabled && current_uid() >= 10000) {
        loff_t pos = ppos ? *ppos : 0;
        size_t avail;

        if (pos < 0) return -EINVAL;
        if (!count || pos >= (loff_t)sizeof(fake_status_bytes)) return 0;

        avail = sizeof(fake_status_bytes) - (size_t)pos;
        if (count > avail) count = avail;

        int rc = compat_copy_to_user(buffer, fake_status_bytes + pos, count);
        if (rc != (int)count) return -EFAULT;
        if (ppos) *ppos = pos + (loff_t)count;
        return (ssize_t)count;
    }
    return orig_sel_read_handle_status(filp, buffer, count, ppos);
}

static int my_sel_mmap_handle_status(struct file *filp, struct vm_area_struct *vma)
{
    if (selinux_hide_enabled && current_uid() >= 10000 && fake_status_vaddr && kfunc(remap_vmalloc_range)) {
        return kfunc(remap_vmalloc_range)(vma, fake_status_vaddr, 0);
    }
    return orig_sel_mmap_handle_status(filp, vma);
}

/* ---- hook install / uninstall ---- */

static int kp_install_hook(unsigned long func, void *replace, void **backup, const char *name)
{
    if (!func) return -ENOENT;
    hook_err_t err = hook((void *)func, replace, backup);
    if (err != HOOK_NO_ERR) {
        logkfw("selinux_hide: hook %s @ %llx error: %d\n", name, func, err);
        return err;
    }
    if (g_hooked_cnt < (int)(sizeof(g_hooked) / sizeof(g_hooked[0]))) g_hooked[g_hooked_cnt++] = func;
    logkfi("selinux_hide: hooked %s @ %llx\n", name, func);
    return 0;
}

static void kp_uninstall_hooks(void)
{
    for (int i = g_hooked_cnt - 1; i >= 0; i--) {
        if (g_hooked[i]) unhook((void *)g_hooked[i]);
        g_hooked[i] = 0;
    }
    g_hooked_cnt = 0;

    orig_context_write = NULL;
    orig_access_write = NULL;
    orig_setprocattr = NULL;
    orig_sel_read_handle_status = NULL;
    orig_sel_mmap_handle_status = NULL;
}

static int selinux_hide_install_hooks(void)
{
    int rc;

    fill_fake_status_bytes();
    init_fake_status();

    rc = kp_install_hook(sel_write_context_addr, (void *)my_write_context, (void **)&orig_context_write,
                         "sel_write_context");
    if (rc) goto err;
    rc = kp_install_hook(sel_write_access_addr, (void *)my_write_access, (void **)&orig_access_write,
                         "sel_write_access");
    if (rc) goto err;
    rc = kp_install_hook(selinux_setprocattr_addr, (void *)my_setprocattr, (void **)&orig_setprocattr,
                         "selinux_setprocattr");
    if (rc) goto err;
    rc = kp_install_hook(sel_read_handle_status_addr, (void *)my_sel_read_handle_status,
                         (void **)&orig_sel_read_handle_status, "sel_read_handle_status");
    if (rc) goto err;
    rc = kp_install_hook(sel_mmap_handle_status_addr, (void *)my_sel_mmap_handle_status,
                         (void **)&orig_sel_mmap_handle_status, "sel_mmap_handle_status");
    if (rc) goto err;

    return 0;
err:
    kp_uninstall_hooks();
    return rc;
}

/* ---- feature API ---- */

int selinux_hide_enable(void)
{
    int rc;
    #ifdef ANDROID
        if (unlikely(android_is_safe_mode)) return -EPERM;
    #endif
    if (!selinux_hide_is_supported()) {
        logkfw("selinux_hide: kernel %x < 4.19, feature not supported\n", kver);
        return -EOPNOTSUPP;
    }
    if (selinux_hide_enabled) return 0;

    rc = selinux_hide_install_hooks();
    if (rc) return rc;

    selinux_hide_enabled = true;
    logkfi("selinux_hide: enabled\n");
    return 0;
}

int selinux_hide_disable(void)
{
    if (!selinux_hide_enabled) return 0;

    kp_uninstall_hooks();
    if (fake_status_vaddr) {
        kp_vfree(fake_status_vaddr);
        fake_status_vaddr = NULL;
    }
    selinux_hide_enabled = false;
    logkfi("selinux_hide: disabled\n");
    return 0;
}

int selinux_hide_is_enabled(void)
{
    return selinux_hide_enabled;
}

long selinux_hide_control(int state)
{
    if (!selinux_hide_is_supported()) return -EOPNOTSUPP;
    if (state < 0) return selinux_hide_enabled ? 1 : 0; /* query: on / off */
    if (state) return selinux_hide_enable();
    return selinux_hide_disable();
}

int selinux_hide_post_fs_data(const char *args)
{
    /* "before" installs the hooks (before a post-fs-data policy reload); a bare
     * "post-fs-data" event (no args) from older managers is treated the same. */
    if (lib_strcmp(args, "before") == 0 || args[0] == '\0') {
        log_boot("selinux_hide: post-fs-data before\n");

        /* The live policy is still the untouched boot policy here: deep-copy it
         * so the context/access/setprocattr hooks answer against the clean policy
         * even after apd/Magisk reloads it. */
        int src = selinux_sepolicy_snapshot();
        log_boot("selinux_sepolicy: snapshot rc=%d\n", src);

        struct file *filp = filp_open(KP_SELINUX_HIDE_FILE, KP_O_RDONLY, 0);
        if (!IS_ERR(filp)) {
            filp_close(filp, 0);
            log_boot("selinux_hide: %s exists, enabling\n", KP_SELINUX_HIDE_FILE);
            selinux_hide_init();
            int rc = selinux_hide_enable();
            log_boot("selinux_hide: enable rc: %d\n", rc);
        }
    } else if (lib_strcmp(args, "after") == 0) {
        log_boot("selinux_hide: post-fs-data after\n");
    }
    return 0;
}

/* ---- symbol lookup helpers (LTO kernels mangle static symbol names) ---- */

struct suffix_lookup
{
    const char *base;
    unsigned long addr;
};

static bool suffix_contains_cfi(const char *suffix)
{
    size_t i;

    for (i = 0; suffix[i]; i++) {
        if (suffix[i] == 'c' && suffix[i + 1] == 'f' && suffix[i + 2] == 'i' &&
            (i == 0 || suffix[i - 1] == '.' || suffix[i - 1] == '$') &&
            (!suffix[i + 3] || suffix[i + 3] == '.' || suffix[i + 3] == '$'))
            return true;
    }
    return false;
}

static bool symbol_has_compiler_suffix(const char *name, const char *base)
{
    size_t i;

    for (i = 0; base[i]; i++) {
        if (name[i] != base[i]) return false;
    }
    if (!(name[i] == '.' || name[i] == '$') || !name[i + 1]) return false;
    if (suffix_contains_cfi(name + i + 1)) return false; /* skip .cfi_jt stubs */
    return true;
}

static int lookup_suffix_cb(void *data, const char *name, struct module *module, unsigned long addr)
{
    struct suffix_lookup *lookup = data;

    (void)module;
    if (!lookup || lookup->addr || !addr) return 0;
    if (!symbol_has_compiler_suffix(name, lookup->base)) return 0;
    lookup->addr = addr;
    return 1;
}

static int lookup_suffix_cb_nomod(void *data, const char *name, unsigned long addr)
{
    struct suffix_lookup *lookup = data;

    if (!lookup || lookup->addr || !addr) return 0;
    if (!symbol_has_compiler_suffix(name, lookup->base)) return 0;
    lookup->addr = addr;
    return 1;
}

static unsigned long lookup_suffix_by_symbol_walk(const char *base)
{
    struct suffix_lookup lookup;

    if (!kallsyms_on_each_symbol) return 0;

    lookup.base = base;
    lookup.addr = 0;

    if (kver <= VERSION(6, 1, 0)) {
        kallsyms_on_each_symbol(lookup_suffix_cb, &lookup);
    } else {
        typedef int (*kallsyms_on_each_symbol_nomod_t)(int (*fn)(void *, const char *, unsigned long), void *data);
        kallsyms_on_each_symbol_nomod_t on_each_symbol =
            (kallsyms_on_each_symbol_nomod_t)kallsyms_on_each_symbol;
        on_each_symbol(lookup_suffix_cb_nomod, &lookup);
    }

    return lookup.addr;
}

unsigned long lookup_name_with_suffix(const char *base)
{
    unsigned long addr;

    addr = kallsyms_lookup_name(base);
    if (addr) return addr;

    /* LLVM LTO mangles static functions to <name>.<n> (or <name>.llvm.<hash>). */
    char name[96];
    size_t i;
    for (u32 n = 0; n < 256; n++) {
        for (i = 0; i < sizeof(name) - 1 && base[i]; i++) name[i] = base[i];
        if (i >= sizeof(name) - 2) return 0;
        name[i++] = '.';
        name[i] = '\0';
        /* append decimal n */
        char buf[12];
        char *p = buf + sizeof(buf);
        u32 v = n;
        do { *--p = (char)('0' + (v % 10)); v /= 10; } while (v);
        while (p < buf + sizeof(buf) && i < sizeof(name) - 1) name[i++] = *p++;
        name[i] = '\0';

        addr = kallsyms_lookup_name(name);
        if (addr) return addr;
    }

    return lookup_suffix_by_symbol_walk(base);
}

int selinux_hide_init(void)
{
    log_boot("selinux_hide: kernel %x, supported: %d\n", kver, selinux_hide_is_supported());

    if (!selinux_hide_is_supported()) return -EOPNOTSUPP;

    selinux_sepolicy_init();

    kp_security_cred_getsecid = (security_cred_getsecid_fn)kallsyms_lookup_name("security_cred_getsecid");

    sel_write_context_addr = kallsyms_lookup_name("sel_write_context");
    if (!sel_write_context_addr) sel_write_context_addr = lookup_name_with_suffix("sel_write_context");
    sel_write_access_addr = kallsyms_lookup_name("sel_write_access");
    if (!sel_write_access_addr) sel_write_access_addr = lookup_name_with_suffix("sel_write_access");
    sel_read_handle_status_addr = kallsyms_lookup_name("sel_read_handle_status");
    if (!sel_read_handle_status_addr) sel_read_handle_status_addr = lookup_name_with_suffix("sel_read_handle_status");
    sel_mmap_handle_status_addr = kallsyms_lookup_name("sel_mmap_handle_status");
    if (!sel_mmap_handle_status_addr) sel_mmap_handle_status_addr = lookup_name_with_suffix("sel_mmap_handle_status");
    selinux_setprocattr_addr = kallsyms_lookup_name("selinux_setprocattr");
    if (!selinux_setprocattr_addr) selinux_setprocattr_addr = lookup_name_with_suffix("selinux_setprocattr");

    log_boot("selinux_hide: sel_write_context: %llx, sel_write_access: %llx, selinux_setprocattr: %llx\n",
             sel_write_context_addr, sel_write_access_addr, selinux_setprocattr_addr);
    log_boot("selinux_hide: sel_read_handle_status: %llx, sel_mmap_handle_status: %llx, cred_getsecid: %llx\n",
             sel_read_handle_status_addr, sel_mmap_handle_status_addr, (unsigned long)kp_security_cred_getsecid);
    return 0;
}
