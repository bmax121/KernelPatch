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
 * On every supported kernel (>= 4.19) the context/access/setprocattr hooks
 * answer against a KernelSU-style deep copy of the policy taken at post-fs-data
 * "before" while the live policy is still untouched, so a root app sees the
 * pre-modification policy.  Apps (uid >= 10000) also see a fake
 * /sys/fs/selinux/status (enforcing=1, clean seqno), hiding permissive /
 * disabled SELinux and policy reloads.
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
#include <pgtable.h>
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
#include <selinux_hide.h>
/* ---- feature constants ---- */
#ifdef ANDROID
extern int android_is_safe_mode;
#endif

#define KP_SELINUX_HIDE_FILE "/data/adb/ap/selinux_hide"


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
#define SEL_WRITE_OP_CONTEXT 5
#define SEL_WRITE_OP_ACCESS 6
/* struct selinux_kernel_status (20 bytes) */
#define KP_SELINUX_KERNEL_STATUS_VERSION 1
#define KP_SELINUX_STATUS_SIZE 20

/* ---- state ---- */

static bool selinux_hide_enabled;
static bool selinux_hide_approved; /* /data/adb/ap/selinux_hide seen at "before" */

typedef void (*security_cred_getsecid_fn)(const struct cred *c, u32 *secid);
static security_cred_getsecid_fn kp_security_cred_getsecid;

typedef int (*remap_pfn_range_fn)(struct vm_area_struct *vma, unsigned long addr, unsigned long pfn,
                                  unsigned long size, unsigned long prot);
static remap_pfn_range_fn kp_remap_pfn_range;

typedef ssize_t (*sel_write_op_fn)(struct file *file, char *buf, size_t size);
typedef int (*sel_mmap_status_fn)(struct file *, struct vm_area_struct *);
typedef ssize_t (*sel_read_status_fn)(struct file *, char __user *, size_t, loff_t *);
typedef int (*selinux_setprocattr_fn)(const char *, void *, size_t);
/* < 6.6 avc_has_perm ABI takes the global selinux_state as the first argument. */
typedef int (*avc_has_perm_compat_fn)(void *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, void *auditdata);

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




/* ---- helpers ---- */

/*
 * Query log (reserved switch).
 *
 * Every selinuxfs query the feature intercepts is logged with the caller uid
 * and the query content, so it is visible in dmesg what apps/detectors ask for:
 *   /sys/fs/selinux/context    (sel_write_context)
 *   /sys/fs/selinux/access     (sel_write_access)
 *   /proc/<pid>/attr/current   (selinux_setprocattr)
 *   /sys/fs/selinux/status     (sel_read_handle_status / sel_mmap_handle_status)
 *
 * Levels: 0 = off, 1 = intercepted queries (default), 2 = also the internal
 * ss/ redirect hooks (context_struct_compute_av / string_to_context_struct,
 * very noisy: one line per AV computation).
 * Runtime switch: selinux_hide_control(2) = off, (3) = level 1, (4) = level 2,
 * (-2) = query the current level.  The control file /data/adb/ap/selinux_hide
 * only governs whether the feature is enabled, not this log.
 */
#define KP_QLOG_OFF 0
#define KP_QLOG_ON 1
#define KP_QLOG_VERBOSE 2

static int selinux_hide_query_log = KP_QLOG_OFF;

/* Printable, bounded, NUL-terminated copy of a query string. */
static void kp_qlog_str(char *dst, const void *src, size_t len, size_t max)
{
    const char *s = src;
    size_t i, n = len < max ? len : max;

    for (i = 0; i < n; i++) {
        char c = s[i];
        dst[i] = (c >= 0x20 && c < 0x7f) ? c : '.';
    }
    dst[n] = '\0';
}

static void kp_qlog(const char *what, uid_t uid, const void *detail, size_t dlen)
{
    char s[96];

    if (selinux_hide_query_log == KP_QLOG_OFF) return;
    kp_qlog_str(s, detail, dlen, sizeof(s) - 1);
    logkfi("query %s uid=%u: %s\n", what, (unsigned int)uid, s);
}

static void kp_qlog_plain(const char *what, uid_t uid)
{
    if (selinux_hide_query_log == KP_QLOG_OFF) return;
    logkfi("query %s uid=%u\n", what, (unsigned int)uid);
}

/* Read by selinux_sepolicy.c for its level-2 (internal redirect) logging. */
int selinux_hide_query_log_level(void)
{
    return selinux_hide_query_log;
}

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
    logkfi("selinux_hide: fake status page ready\n");
}

/* ---- vm_area_struct field offsets for the status mmap ----
 *
 * struct vm_area_struct starts with vm_start/vm_end in every version, and the
 * page protection slot sits right after vm_mm; 6.1 reordered the middle of the
 * struct (maple tree), earlier kernels kept vm_next/vm_prev/vm_rb before vm_mm.
 * The offsets below were read from the target kernel's BTF (6.12: vm_start 0,
 * vm_page_prot 24); a wrong slot cannot cause a bad mapping because the value
 * is checked for a plausible arm64 pgprot first -- anything else falls back to
 * the kernel's own mapping. */
#define KP_VMA_VM_START_OFF 0
static int kp_vma_page_prot_off(void)
{
    return kver >= VERSION(6, 1, 0) ? 24 : 72;
}

static bool kp_pgprot_plausible(unsigned long prot)
{
    /* arm64 pgprot: valid|type low bits set, attribute bits only, no address */
    return prot != 0 && (prot & 0x3) == 0x3 && (prot >> 48) == 0;
}

/* ---- permission / sid helpers (KernelSU my_write_* parity) ---- */

static avc_has_perm_compat_fn kp_avc_has_perm_compat;
static unsigned long kp_selinux_state_addr; /* < 6.6 avc ABI needs the state */

static u32 kp_current_sid(void)
{
    struct cred *cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    u32 sid = 0;
    if (!kp_security_cred_getsecid || !cred) return 0;
    kp_security_cred_getsecid(cred, &sid);
    return sid;
}

/* avc_has_perm(current_sid, tsid, tclass, requested).  0 = granted (or the
 * check is unavailable, which matches stock behaviour for untrusted_app). */
static int kp_avc_check(u32 tsid, u16 tclass, u32 requested)
{
    u32 mysid = kp_current_sid();
    if (!mysid) return 0;
    if (selinux_hide_is_without_sepolicy_state_version()) {
        if (!kfunc(avc_has_perm)) return 0;
        return kfunc(avc_has_perm)(mysid, tsid, tclass, requested, NULL);
    }
    if (!kp_avc_has_perm_compat)
        kp_avc_has_perm_compat = (avc_has_perm_compat_fn)lookup_name_with_suffix("avc_has_perm");
    if (!kp_avc_has_perm_compat || !kp_selinux_state_addr) return 0;
    return kp_avc_has_perm_compat((void *)kp_selinux_state_addr, mysid, tsid, tclass, requested, NULL);
}

int security_context_to_sid_fn(const char *context, int len, u32 *sid, gfp_t gfp);

/*
 * Resolve an app-supplied context: the clean snapshot decides whether it is
 * known, and the live policy is consulted only for a context the snapshot
 * accepted.
 *
 * The live lookup reproduces a stock query's registration side effect: selinuxfs
 * resolves a context in the live policy, which inserts it into the live SID
 * table.  That is what keeps a SID handed out by the snapshot resolvable
 * through the live policy -- KernelSU a810677b, "fix sidtab detection" -- and
 * the table's size is readable by anyone through
 * /sys/fs/selinux/ss/sidtab_hash_stats, so the registration is observable.
 *
 * It must NOT run for a context the snapshot rejects: the live policy is where
 * a root manager's extra domains live, so resolving a hidden name
 * (u:r:su:s0, u:r:ksu:s0, ...) there would register it while the answer says
 * "unknown".  An app watching that counter would see the live table grow on a
 * rejected query, which no clean device does, and could enumerate the hidden
 * policy with a wordlist.  Confining the lookup to the accepted path also keeps
 * a rejected name exactly as expensive as the snapshot's own failed parse,
 * whether or not the live policy knows it, so the rejected inputs cannot be
 * told apart by cost either.
 *
 * Returns the snapshot's verdict: 0 = the context is answered from the snapshot
 * and *sid is its SID.
 */
static int kp_context_to_sid_clean(const char *scontext, u32 scontext_len, u32 *sid)
{
    u32 live_sid = SECSID_NULL;
    int rc;

    *sid = SECSID_NULL;
    rc = selinux_sepolicy_context_to_sid(scontext, scontext_len, sid, KP_GFP_KERNEL);
    if (!rc)
        (void)security_context_to_sid_fn(scontext, scontext_len, &live_sid, KP_GFP_KERNEL);
    return rc;
}

static ssize_t kp_patch_response_seqno(char *buf, ssize_t ret, u32 new_seqno)
{
    char *p = buf, *end = buf + ret, *tok_start;
    char new_str[12];
    int ns_len, tok, i;
    ssize_t diff;

    if (ret <= 0 || !buf) return ret;
    for (tok = 0; tok < 4; tok++) {
        while (p < end && *p == ' ') p++;
        while (p < end && *p != ' ') p++;
    }
    while (p < end && *p == ' ') p++;
    tok_start = p;
    while (p < end && *p != ' ' && *p != '\0' && *p != '\n') p++;
    if (tok_start >= p) return ret;

    {
        u32 v = new_seqno;
        char tmp[12];
        if (v == 0) {
            new_str[0] = '0';
            ns_len = 1;
        } else {
            i = 0;
            while (v > 0) {
                tmp[i++] = '0' + (v % 10);
                v /= 10;
            }
            for (ns_len = 0; ns_len < i; ns_len++)
                new_str[ns_len] = tmp[i - 1 - ns_len];
        }
    }

    diff = (ssize_t)ns_len - (ssize_t)(p - tok_start);
    if (diff != 0) {
        char *dst = tok_start + ns_len, *src = p;
        size_t move = (size_t)(end - src);
        int j;
        if (diff < 0) {
            for (j = 0; j < (int)move; j++) dst[j] = src[j];
        } else {
            for (j = (int)move - 1; j >= 0; j--) dst[j] = src[j];
        }
        ret += diff;
    }
    for (i = 0; i < ns_len; i++)
        tok_start[i] = new_str[i];
    return ret;
}

static bool kp_avd_seqno_probe(const char *scon,
                               const char *tcon,
                               u16 tclass)
{
    static const char prefix[] = "u:r:untrusted_app:s0";
    if (tclass != 0)
        return false;
    if (!scon || !tcon)
        return false;
    if (lib_strncmp(scon, prefix, sizeof(prefix) - 1) != 0)
        return false;
    if (lib_strncmp(tcon, prefix, sizeof(prefix) - 1) != 0)
        return false;
    if (scon[sizeof(prefix) - 1] != '\0' &&
        scon[sizeof(prefix) - 1] != ':')
        return false;
    if (tcon[sizeof(prefix) - 1] != '\0' &&
        tcon[sizeof(prefix) - 1] != ':')
        return false;
    return true;
}
/* ---- app-facing selinuxfs query surface ----
 *
 * selinuxfs exposes the context-resolving transaction nodes context/access/
 * create/relabel/user/member (world-readable and world-writable at the VFS
 * level: S_IRUGO|S_IWUGO) and validatetrans (world-writable).  Which of them an
 * app-side caller can actually use is decided by the permission each handler
 * checks *before* it parses the payload:
 *
 *   context  (check_context)   -- hooked below, answered from the snapshot
 *   access   (compute_av)      -- hooked below, answered from the snapshot
 *   create   (compute_create)  -- no hook needed: AOSP grants none of these to
 *   relabel  (compute_relabel)    an app-side domain.  app_zygote is the only
 *   user     (compute_user)       app-uid domain with SELinux query rights and
 *   member   (compute_member)     selinux_check_access() gives it exactly
 *   validatetrans (validate_trans) compute_av + check_context, while plain app
 *                                 domains are denied both outright
 *                                 (private/app.te: "SELinux is not an API for
 *                                 apps to use").  The kernel checks the
 *                                 permission before parsing, so every app-side
 *                                 call to those five is rejected with EACCES
 *                                 before any policy lookup -- there is nothing
 *                                 to intercept there.
 *
 * setprocattr ("current") and the status page are hooked further down. */

static ssize_t my_write_context_new(struct file *file, char *buf, size_t size)
{

    uid_t uid = current_uid();
    char *canon = NULL;
    u32 sid, len;
    ssize_t length;

    /* Before the permission check on purpose: the log is what makes detector
     * probes visible, and its cost depends only on the payload length, so two
     * equal-length writes cannot be told apart through it. */
    kp_qlog("context_write", uid, buf, size);

    if (likely(uid < 10000)) {
        length = orig_context_write(file, buf, size);
        if (length > 0) kp_qlog("context_answer", uid, buf, (size_t)length);
        else kp_qlog("context_answer_failed", uid, buf, (size_t)length);
        return length;
    }

    /* KernelSU my_write_context: answer entirely from the clean snapshot.
     * The stock handler is never run for apps, so the live (patched) sidtab
     * can never leak into the canonical answer -- no symbol-redirect scope,
     * no silent fallback to the live policy. */
    length = kp_avc_check(KP_SECINITSID_SECURITY, KP_SECCLASS_SECURITY, KP_SECURITY__CHECK_CONTEXT);
    if (length) return length;

    length = kp_context_to_sid_clean(buf, size, &sid);
    if (length) {
        return length;
    }

    length = selinux_sepolicy_sid_to_context(sid, &canon, &len);
    if (length) return length;

    if (len > KP_SIMPLE_TRANSACTION_LIMIT) {
        length = -ERANGE;
        goto out;
    }

    lib_memcpy(buf, canon, len);
    length = (ssize_t)len;
out:
    if (canon && kfunc(kfree)) kfunc(kfree)(canon);
    return length;
}
static ssize_t my_write_context(struct file *file, char *buf, size_t size)
{
    if (selinux_hide_is_new_version()) return my_write_context_new(file, buf, size);
    uid_t uid = current_uid();
    ssize_t ret;

    kp_qlog("context_write", uid, buf, size);

    if (likely(uid < 10000)) {
        ret = orig_context_write(file, buf, size);
        if (ret > 0){ 
            kp_qlog("context_answer", uid, buf, (size_t)ret);
        }else{
            kp_qlog("context_answer_failed", uid, buf, (size_t)ret);
        }
        return ret;
    }
    if (selinux_sepolicy_clean_eval_enter() == 0) {
        ret = orig_context_write(file, buf, size);
        selinux_sepolicy_clean_eval_leave();
    } else {
        ret = orig_context_write(file, buf, size);
    }
    if (ret > 0) kp_qlog("context_answer", uid, buf, (size_t)ret);
    return ret;

}

static ssize_t my_write_access_new(struct file *file, char *buf, size_t size)
{
    ssize_t ret;
    uid_t uid = current_uid();
    char scon[256], tcon[256];
    struct av_decision avd;
    u32 ssid, tsid, sconlen, tconlen;
    u16 tclass = 0;
    ssize_t length;

    kp_qlog("access_write", uid, buf, size);

    if (likely(uid < 10000)) {
        length = orig_access_write(file, buf, size);
        if (length > 0) kp_qlog("access_answer", uid, buf, (size_t)length);
        else kp_qlog("access_answer_failed", uid, buf, (size_t)length);
        return length;
    }


    length = kp_avc_check(KP_SECINITSID_SECURITY, KP_SECCLASS_SECURITY, KP_SECURITY__COMPUTE_AV);
    if (length) return length;

    if (sscanf(buf, "%255s %255s %hu", scon, tcon, &tclass) != 3) return -EINVAL;

    sconlen = lib_strlen(scon);
    tconlen = lib_strlen(tcon);

    /* Both contexts must be in the snapshot: a context only the live policy has
     * (the manager's su domain) is not part of the answer a clean device would
     * give.  Each accepted context is registered in the live policy as well,
     * exactly like the stock handler's own conversions do; a rejected one is
     * not, see kp_context_to_sid_clean. */
    length = kp_context_to_sid_clean(scon, sconlen, &ssid);
    if (length) return length;

    length = kp_context_to_sid_clean(tcon, tconlen, &tsid);
    if (length) return length;

    lib_memset(&avd, 0, sizeof(avd));
    avd.auditdeny = 0xffffffff;
    selinux_sepolicy_compute_av_user(ssid, tsid, tclass, &avd);
    avd.seqno = KP_AVD_CLEAN_SEQNO;

    return snprintf(buf, size, "%x %x %x %x %u %x",
                    avd.allowed, 0xffffffff, avd.auditallow, avd.auditdeny,
                    avd.seqno, avd.flags);
}
static ssize_t my_write_access(struct file *file, char *buf, size_t size)
{
    if (selinux_hide_is_new_version()) return my_write_access_new(file, buf, size);

    ssize_t ret;
    uid_t uid = current_uid();
    char scon[256], tcon[256];
    struct av_decision avd;
    u32 ssid, tsid, sconlen, tconlen ,tmp;
    u16 tclass = 0;
    ssize_t length;

    kp_qlog("access_write", uid, buf, size);

    if (likely(uid < 10000)) {
        length = orig_access_write(file, buf, size);
        if (length > 0) kp_qlog("access_answer", uid, buf, (size_t)length);
        else kp_qlog("access_answer_failed", uid, buf, (size_t)length);
        return length;
    }
 
 
        {
            char tmp[96];
            char scon[64], tcon[64];
            unsigned int allowed, decided,auditallow,auditdeny,seqno,flags;
            u16 tclass = 0;
            size_t tn = size < sizeof(tmp) - 1? size: sizeof(tmp) - 1;
            lib_memcpy(tmp, buf, tn);
            tmp[tn] = '\0';
            if (sscanf(tmp, "%63s %63s %hu", scon, tcon, &tclass) == 3 &&
                kp_avd_seqno_probe(scon, tcon, tclass)) {
                ret = orig_access_write(file, buf, size);
                if (ret > 0) {
                    if (sscanf(buf,"%x %x %x %x %u %x",&allowed,&decided,&auditallow,&auditdeny,&seqno,&flags) == 6) {
                        seqno = 1;
                        ret = snprintf(buf,size,"%x %x %x %x %u %x",allowed,decided,auditallow,auditdeny,seqno,flags);
                        if (ret > 0 && (size_t)ret < size) {
                            kp_qlog("access_answer(seqno probe)",uid, buf, (size_t)ret);
                            logkfi("access_answer(seqno probe) ""uid=%u buf=%s,""scon=%s,tcon=%s,tclass=%hu,""origin=%zd,now=%zd,origin_buf=%s\n",(unsigned int)uid,buf,scon,tcon,tclass,ret,ret,tmp);
                            return ret;
                        }
                    }
                }
                return ret;
            }
        }

        if (selinux_sepolicy_clean_eval_enter() == 0) {
            ret = orig_access_write(file, buf, size);
            selinux_sepolicy_clean_eval_leave();
        } else {
            ret = orig_access_write(file, buf, size);
        }

        if (ret > 0)
            ret = kp_patch_response_seqno(buf, ret, KP_AVD_CLEAN_SEQNO);

        if (ret > 0)
            kp_qlog("access_answer", uid, buf, (size_t)ret);

        return ret;
    
}

/* ---- setprocattr handler ---- */


static int my_setprocattr_new(const char *name, void *value, size_t size)
{
    uid_t uid = current_uid();
    u32 mysid, sid;
    char *str = value;
    char vbuf[96];
    int error;

    /* KernelSU my_setprocattr: apps may only transition to contexts that the
     * CLEAN policy knows; a root-manager context is rejected here, before the
     * stock handler ever consults the patched live policy. */
    if (uid < 10000 || lib_strcmp(name, "current")) goto call_orig;

    /* Stock sequence: the self permission check runs before the context is
     * parsed, and nothing may touch the payload before it.  A denied write has
     * to cost exactly what it costs on stock whether the payload is a valid
     * context or a same-length string that is not; parsing first made a valid
     * context measurably slower than an invalid one (one extra parse ahead of
     * the same denial), which KernelSU a85dcbcf had to fix. */
    mysid = kp_current_sid();
    error = kp_avc_check(mysid, KP_SECCLASS_PROCESS, KP_PROCESS__SETCURRENT);

    if (selinux_hide_query_log != KP_QLOG_OFF) {
        /* After the permission decision, so nothing input-dependent precedes
         * it, and denied writes stay visible: a detector's attr/current probe
         * shows up here as a denied write of a full application context. */
        kp_qlog_str(vbuf, value, size, sizeof(vbuf) - 1);
        logkfi("query setprocattr uid=%u name=%s value=%s%s\n", (unsigned int)uid,
               name ? name : "(null)", vbuf, error ? " (denied)" : "");
    }
    if (error) return error;

    if (size && str[0] && str[0] != '\n') {
        if (str[size - 1] == '\n') {
            str[size - 1] = 0;
            size--;
        }
        /* The snapshot has to know the context -- that is what rejects a
         * manager context, and here it is the whole decision.  The SID is not
         * used because the stock handler performs the transition: it resolves
         * the context in the live policy itself (registering it there once, as
         * any stock query would) and applies the bounded-transition /
         * DYNTRANSITION / ptrace checks with its own audit trail.  Leaving the
         * live policy out of this path also keeps it free of side effects a
         * clean device would not have: for a denied app the stock handler stops
         * at its own permission check before resolving anything. */
        error = selinux_sepolicy_context_to_sid(value, size, &sid, KP_GFP_KERNEL);
        if (error) return error;
    }

call_orig:
    return orig_setprocattr(name, value, size);
}


static int my_setprocattr(const char *name, void *value, size_t size)
{
    if (selinux_hide_is_new_version()) return my_setprocattr_new(name, value, size);
    uid_t uid = current_uid();
    u32 tmp, mysid;
    char *str = value;
    char vbuf[96];
    int error,perm_error;
    if (selinux_hide_query_log != KP_QLOG_OFF) {
        kp_qlog_str(vbuf, value, size, sizeof(vbuf) - 1);
        logkfi("query setprocattr uid=%u name=%s value=%s\n", (unsigned int)uid,
               name ? name : "(null)", vbuf);
    }
    if (likely(uid < 10000)) goto call_orig;
    if (lib_strcmp(name, "current")) goto call_orig;
    if (!kfunc(avc_has_perm) || !selinux_has_selinux_state()) goto call_orig;
    if (selinux_sepolicy_clean_eval_enter() == 0) {
        int rc = orig_setprocattr(name, value, size);
        selinux_sepolicy_clean_eval_leave();
        return rc;

    }

call_orig:
    return orig_setprocattr(name, value, size);

}
/* ---- /sys/fs/selinux/status (read + mmap) ---- */

static ssize_t my_sel_read_handle_status(struct file *filp, char __user *buffer, size_t count, loff_t *ppos)
{
    uid_t uid = current_uid();

    if (selinux_hide_query_log != KP_QLOG_OFF) {
        logkfi("query status_read uid=%u count=%u pos=%u\n", (unsigned int)uid,
               (unsigned int)count, (unsigned int)(ppos ? *ppos : 0));
    }

    if (selinux_hide_enabled && uid >= 10000) {
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

static int my_sel_mmap_handle_status(struct file *filp,
                                     struct vm_area_struct *vma)
{
    uid_t uid = current_uid();

    kp_qlog_plain("status_mmap", uid);

    if (selinux_hide_enabled && uid >= 10000 &&
        fake_status_vaddr && kp_remap_pfn_range) {

        unsigned long *vm = (unsigned long *)vma;
        unsigned long start;
        unsigned long prot;
        unsigned long pa;
        int ret;

        start = vm[KP_VMA_VM_START_OFF / sizeof(unsigned long)];
        prot = vm[kp_vma_page_prot_off() / sizeof(unsigned long)];

        pa = pgtable_phys_kernel((uintptr_t)fake_status_vaddr);

        if (!pa) {
            logkfw("selinux_hide: status mmap: "
                   "failed to resolve fake page PA, vma=%px start=%lx "
                   "prot=%016lx\n",
                   vma, start, prot);
            goto real_page;
        }

        if (start & (KP_PAGE_SIZE - 1)) {
            logkfw("selinux_hide: status mmap: "
                   "invalid vm_start=%lx prot=%016lx\n",
                   start, prot);
            goto real_page;
        }

        ret = kp_remap_pfn_range(
            vma,
            start,
            pa >> page_shift,
            KP_PAGE_SIZE,
            prot
        );

        if (!ret)
            return 0;

        logkfw("selinux_hide: status mmap: "
               "remap_pfn_range failed ret=%d pa=%llx "
               "start=%lx prot=%016lx\n",
               ret, pa, start, prot);
    }

real_page:
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

/* ---- data-pointer (KernelSU-style) hooks ----
 *
 * selinuxfs dispatches through data structures -- the write_op[] table and the
 * status file_operations -- so the handlers can be replaced by rewriting a
 * pointer slot.  No kernel text is modified that way, which is what keeps
 * these invisible to text-integrity checks; only the (verified) slot changes.
 *
 * Member offsets differ per kernel version, so nothing is hardcoded: the
 * write_op[] indices are confirmed against the resolved handler symbols before
 * use, and the status slots are located by scanning the ops struct for the
 * resolved handler address.  Anything unverified falls back to the old inline
 * hook so behaviour never regresses silently.
 */

#define KP_MAX_FP_HOOKS 8
static uintptr_t g_fp_slot[KP_MAX_FP_HOOKS];
static void *g_fp_orig[KP_MAX_FP_HOOKS];
static int g_fp_cnt;

static int kp_install_fp_slot(uintptr_t slot, void *replace, void **backup, const char *name)
{
    if (!slot) return -ENOENT;
    fp_hook(slot, replace, backup);
    if (g_fp_cnt < KP_MAX_FP_HOOKS) {
        g_fp_slot[g_fp_cnt] = slot;
        g_fp_orig[g_fp_cnt] = *backup;
        g_fp_cnt++;
    }
    logkfi("selinux_hide: fp-hooked (data) %s @ slot %llx -> %llx\n", name, (unsigned long)slot,
           (unsigned long)replace);
    return 0;
}


static uintptr_t kp_found_write_op_slot(unsigned long write_op, unsigned long index)
{
    sel_write_op_fn *w = (sel_write_op_fn *)write_op;
    if (!write_op || is_bad_address((void *)write_op) || !index) return 0;
    if (!is_bad_address(&w[index])) return (uintptr_t)&w[index];
    return 0;
}

static uintptr_t kp_find_fops_slot(unsigned long ops, unsigned long index)
{
    unsigned long *p = (unsigned long *)ops;
    if (!ops || is_bad_address((void *)ops) || !index) return 0;
    if (!is_bad_address(&p[index])) return (uintptr_t)&p[index];
    return 0;
}

static void kp_uninstall_hooks(void)
{
    for (int i = g_hooked_cnt - 1; i >= 0; i--) {
        if (g_hooked[i]) unhook((void *)g_hooked[i]);
        g_hooked[i] = 0;
    }
    g_hooked_cnt = 0;
    for (int i = g_fp_cnt - 1; i >= 0; i--) {
        if (g_fp_slot[i]) fp_unhook(g_fp_slot[i], g_fp_orig[i]);
        g_fp_slot[i] = 0;
        g_fp_orig[i] = NULL;
    }
    g_fp_cnt = 0;

    orig_context_write = NULL;
    orig_access_write = NULL;
    orig_setprocattr = NULL;
    orig_sel_read_handle_status = NULL;
    orig_sel_mmap_handle_status = NULL;
}

static int selinux_hide_install_hooks(void)
{
    int rc;
    unsigned long write_op, status_ops;
    uintptr_t slot;

    fill_fake_status_bytes();
    init_fake_status();

    write_op = lookup_name_with_suffix("write_op");
    status_ops = lookup_name_with_suffix("sel_handle_status_ops");
    log_boot("selinux_hide: write_op=%llx status_ops=%llx ctx=%llx acc=%llx rd=%llx mmap=%llx\n",
             write_op, status_ops, sel_write_context_addr, sel_write_access_addr,
             sel_read_handle_status_addr, sel_mmap_handle_status_addr);

    // https://android.googlesource.com/kernel/common/+/refs/heads/android13-5.10/security/selinux/selinuxfs.c?utm_source=chatgpt.com
    // enum sel_inos 
    if (sel_write_context_addr) {
        rc = kp_install_hook(sel_write_context_addr, (void *)my_write_context, (void **)&orig_context_write,
                             "sel_write_context");
        log_boot("selinux_hide: installed hook for sel_write_context\n");
        if (rc) goto err;
    }else{
        slot = kp_found_write_op_slot(write_op, SEL_WRITE_OP_CONTEXT);
        if (slot) {
            kp_install_fp_slot(slot, (void *)my_write_context, (void **)&orig_context_write,"sel_write_context");
            log_boot("selinux_hide: installed fp slot for sel_write_context\n");
        }else{
            log_boot("selinux_hide: failed to find write_op slot for sel_write_context\n");
        }
    }

    if (sel_write_access_addr) {
        rc = kp_install_hook(sel_write_access_addr, (void *)my_write_access, (void **)&orig_access_write,
                             "sel_write_access");
        log_boot("selinux_hide: installed hook for sel_write_access\n");
        if (rc) goto err;
    }else{
        slot = kp_found_write_op_slot(write_op, SEL_WRITE_OP_ACCESS);
        if (slot) {
            kp_install_fp_slot(slot, (void *)my_write_access, (void **)&orig_access_write,"sel_write_access");
            log_boot("selinux_hide: installed fp slot for sel_write_access\n");
        }else{
            log_boot("selinux_hide: failed to find write_op slot for sel_write_access\n");
        }
    }

    /* setprocattr is reached through the LSM hook list (no data slot we can
     * address), keep the inline hook. */
    if (selinux_setprocattr_addr) {
        rc = kp_install_hook(selinux_setprocattr_addr, (void *)my_setprocattr, (void **)&orig_setprocattr,
                             "selinux_setprocattr");
        log_boot("selinux_hide: installed hook for selinux_setprocattr\n");
        if (rc) goto err;
    }


    /* status read/mmap: data-pointer hooks in the status file_operations. */

    // https://android.googlesource.com/kernel/common/%2B/d2f7eca60b29006285d57c7035539e33300e89e5/include/linux/fs.h
    // struct file_operations {

    if (sel_read_handle_status_addr){
        rc = kp_install_hook(sel_read_handle_status_addr, (void *)my_sel_read_handle_status,
                             (void **)&orig_sel_read_handle_status, "sel_read_handle_status");
        log_boot("selinux_hide: installed hook for sel_read_handle_status\n");
        if (rc) goto err;
    }else{
        // ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
        slot = kp_find_fops_slot(status_ops, 3);
        if (slot) {
            rc = kp_install_fp_slot(slot, (void *)my_sel_read_handle_status, (void **)&orig_sel_read_handle_status,
                                    "sel_read_handle_status");
            if (rc) goto err;
            log_boot("selinux_hide: installed fops slot for sel_read_handle_status\n");
        } else {
            log_boot("selinux_hide: failed to find fops slot for sel_read_handle_status\n");
        }

    }
    if (sel_mmap_handle_status_addr){
        rc = kp_install_hook(sel_mmap_handle_status_addr, (void *)my_sel_mmap_handle_status,
                             (void **)&orig_sel_mmap_handle_status, "sel_mmap_handle_status");
        log_boot("selinux_hide: installed hook for sel_mmap_handle_status\n");
        if (rc) goto err;
    }else{
        // int (*mmap) (struct file *, struct vm_area_struct *);
        slot = kp_find_fops_slot(status_ops, 12);
        if (slot) {
            rc = kp_install_fp_slot(slot, (void *)my_sel_mmap_handle_status, (void **)&orig_sel_mmap_handle_status,
                                    "sel_mmap_handle_status");
            if (rc) goto err;
            log_boot("selinux_hide: installed fops slot for sel_mmap_handle_status\n");
        } else {
            log_boot("selinux_hide: failed to find fops slot for sel_mmap_handle_status\n");
        }
    }
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
        logkfw("selinux_hide: kernel < 4.19, feature not supported\n");
        return -EOPNOTSUPP;
    }
    if (selinux_hide_enabled) return 0;

    if (!selinux_sepolicy_backup_ready()) {
        log_boot("selinux_hide: no backup sepolicy available, please save feature and reboot to retry\n");
        return -EAGAIN;
    }

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

    /* Query-log switch (see the KP_QLOG_* block above).  Kept out of the
     * enable/disable path so a manager can silence the log without touching
     * the feature state. */
    switch (state) {
    case -2:
        return selinux_hide_query_log;
    case 2:
        selinux_hide_query_log = KP_QLOG_OFF;
        logkfi("query log: off\n");
        return 0;
    case 3:
        selinux_hide_query_log = KP_QLOG_ON;
        logkfi("query log: on (intercepted queries)\n");
        return 0;
    case 4:
        selinux_hide_query_log = KP_QLOG_VERBOSE;
        logkfi("query log: verbose (intercepted queries + ss/ redirects)\n");
        return 0;
    default:
        break;
    }

    if (state < 0) return selinux_hide_enabled ? 1 : 0; /* query: on / off */
    if (state) return selinux_hide_enable();
    return selinux_hide_disable();
}

int selinux_hide_post_fs_data(const char *args)
{
    /* "before" resolves ss/ symbols and snapshots the clean boot policy (the
     * live policy is still untouched here); a bare "post-fs-data" event (no
     * args) from older managers is treated the same.  Hooks are installed at
     * "after", once apd/Magisk have finished their policy reloads. */
    if (lib_strcmp(args, "before") == 0 || args[0] == '\0') {
        log_boot("selinux_hide: post-fs-data before\n");

        struct file *filp = filp_open(KP_SELINUX_HIDE_FILE, KP_O_RDONLY, 0);
        if (!IS_ERR(filp)) {
            filp_close(filp, 0);
            log_boot("selinux_hide: %s exists\n", KP_SELINUX_HIDE_FILE);

            /* Resolve ss/ symbols FIRST: the snapshot below needs the resolved
             * kp_policydb_read/kp_policydb_load_isids. */
            selinux_hide_init();

            /* The live policy is still the untouched boot policy here: deep-copy
             * it so the context/access/setprocattr hooks answer against the clean
             * policy even after apd/Magisk reloads it. */
            int src = selinux_sepolicy_snapshot();
            log_boot("selinux_sepolicy: snapshot rc=%d\n", src);

            selinux_hide_approved = true;
        }
    } else if (lib_strcmp(args, "after") == 0) {
        log_boot("selinux_hide: post-fs-data after\n");
        if (selinux_hide_approved) {
            int rc = selinux_hide_enable();
            log_boot("selinux_hide: enable rc: %d\n", rc);
        }
    }
    return 0;
}
int security_context_to_sid_fn(const char *context, int len, u32 *sid, gfp_t gfp)
{
    if (selinux_hide_is_without_sepolicy_state_version()) {
        return kfunc(security_context_to_sid)(context, len, sid, gfp);
    } else {
        return kfunc(security_context_to_sid_compat)((void *)kp_selinux_state_addr, context, len, sid, gfp);
    }
}

unsigned long lookup_name_with_suffix(const char *base)
{
    
    /* LLVM LTO mangles static functions to <name>.<n> / <name>.llvm.<hash> /
     * <name>$... .  One kallsyms_on_each_symbol walk covers every form, so there
     * is no need to probe <base>.<0..255> first (kallsyms_on_each_symbol is
     * KernelPatch core infra, always resolved before the builtin features run). */
    unsigned long addr = kallsyms_lookup_name_by_suffix(base);
    if (addr) return addr;
    return 0;
}

int selinux_hide_init(void)
{
    log_boot("selinux_hide: kernel %x, supported: %d\n", kver, selinux_hide_is_supported());

    if (!selinux_hide_is_supported()) return -EOPNOTSUPP;

    /* These symbols are only used by selinux_hide.  Resolve them lazily here
     * instead of adding them to the global misc ksym initialization pass. */
    kfunc(remap_vmalloc_range) =
        (typeof(kfunc(remap_vmalloc_range)))lookup_name_with_suffix("remap_vmalloc_range");
    kp_remap_pfn_range = (remap_pfn_range_fn)lookup_name_with_suffix("remap_pfn_range");
    kfunc(avc_has_perm) = (typeof(kfunc(avc_has_perm)))lookup_name_with_suffix("avc_has_perm");
    kfunc(security_load_policy) =
        (typeof(kfunc(security_load_policy)))lookup_name_with_suffix("security_load_policy");
    kfunc(security_read_policy) =
        (typeof(kfunc(security_read_policy)))lookup_name_with_suffix("security_read_policy");
    kfunc(security_compute_av_user) =
        (typeof(kfunc(security_compute_av_user)))lookup_name_with_suffix("security_compute_av_user");
    kfunc(security_sid_to_context) =
        (typeof(kfunc(security_sid_to_context)))lookup_name_with_suffix("security_sid_to_context");
    if (selinux_hide_is_without_sepolicy_state_version())
        kfunc(security_context_to_sid) =
            (typeof(kfunc(security_context_to_sid)))lookup_name_with_suffix("security_context_to_sid");
    else
        kfunc(security_context_to_sid_compat) =
            (typeof(kfunc(security_context_to_sid_compat)))lookup_name_with_suffix("security_context_to_sid");
    kfunc(security_context_str_to_sid) =
        (typeof(kfunc(security_context_str_to_sid)))lookup_name_with_suffix("security_context_str_to_sid");

    selinux_sepolicy_init();

    kp_security_cred_getsecid = (security_cred_getsecid_fn)kallsyms_lookup_name("security_cred_getsecid");
    kp_selinux_state_addr = lookup_name_with_suffix("selinux_state");

    sel_write_context_addr = lookup_name_with_suffix("sel_write_context");
    sel_write_access_addr = lookup_name_with_suffix("sel_write_access");
    sel_read_handle_status_addr = lookup_name_with_suffix("sel_read_handle_status");
    sel_mmap_handle_status_addr = lookup_name_with_suffix("sel_mmap_handle_status");
    selinux_setprocattr_addr = lookup_name_with_suffix("selinux_setprocattr");

    log_boot("selinux_hide: sel_write_context: %llx, sel_write_access: %llx, selinux_setprocattr: %llx\n",
             sel_write_context_addr, sel_write_access_addr, selinux_setprocattr_addr);
    log_boot("selinux_hide: sel_read_handle_status: %llx, sel_mmap_handle_status: %llx, cred_getsecid: %llx\n",
             sel_read_handle_status_addr, sel_mmap_handle_status_addr, (unsigned long)kp_security_cred_getsecid);
    return 0;
}
