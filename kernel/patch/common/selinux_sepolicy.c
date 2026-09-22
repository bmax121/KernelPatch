/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 *
 * Deep copy of the clean SELinux policy, in the spirit of KernelSU's
 * ksu_dup_sepolicy()/backup_sepolicy: serialize the (still stock) live policy
 * with security_read_policy(), rebuild a fully independent policydb from the
 * blob with policydb_read(), restore the serialized length and load the initial
 * SIDs into our own sidtab.  policydb_read() rebuilds every inner table
 * (symtabs, val_to_struct maps, avtabs, hashtabs, ebitmaps, cond lists), so the
 * copy owns all of its pointers and needs no fixup loops -- unlike a shallow
 * struct copy, which would share them with the live policy.
 *
 * The copy is consumed through the ss/ wrappers below (policydb + sidtab passed
 * explicitly), so the same code serves every supported kernel; no fake
 * struct selinux_state is involved.
 *
 * AOSP Android config bits: policydb_write() (called inside
 * security_read_policy()) is hooked by patch/android/sepolicy_flags.c, which
 * ORs android_netlink_route/getneigh into the serialized config -- the same fix
 * KernelSU applies by patching the blob's config word at offset 20.
 *
 * NOTE: we deliberately do NOT use security_load_policy() for the copy -- it
 * starts an async sidtab-conversion workqueue that cannot be safely cancelled
 * and wedges the workqueue pool, freezing the system.
 */

#include <selinux_sepolicy.h>
#include <selinux_hide.h> /* lookup_name_with_suffix */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>
#include <predata.h>
#include <kputils.h>
#include <baselib.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/err.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include <security/selinux/include/security.h>
#include <security/selinux/include/avc.h>

/* ---- constants ---- */

#define KP_SEPOLICY_MIN_VERSION VERSION(4, 19, 0)
#define KP_SEPOLICY_WITH_POLICY_MIN_VERSION VERSION(6, 4, 0) /* helpers drop the state arg here */

#define KP_POLICY_POLICYDB_OFFSET (sizeof(void *)) /* struct selinux_policy { sidtab*, policydb, ... } */
/* Heap allocations for the copy (KernelSU uses kmemdup/vmalloc the same way).
 * Generous margins: kernel code writes the structs at its own compiled offsets
 * and the real structs may be larger than the layouts declared below. */
#define KP_BACKUP_POLICY_SIZE 0x8000 /* standalone policydb + wrapper */
#define KP_BACKUP_SIDTAB_SIZE 0x4000 /* struct sidtab (hash roots etc.) */
#define KP_GFP_KERNEL 0xcc0u /* __GFP_RECLAIM | __GFP_IO | __GFP_FS */

/* ---- SELinux ss/ structures (layouts from the kpm selinux_hook module) ---- */

struct policy_file
{
    char *data;
    size_t len;
};

struct flex_array;
struct hashtab;

struct symtab
{
    struct hashtab *table;
    u32 nprim;
};

enum
{
    SELINUX_EBITMAP_NODE_SIZE = 64,
    SELINUX_EBITMAP_UNIT_BITS = sizeof(unsigned long) * 8,
    SELINUX_EBITMAP_UNIT_NUMS = (SELINUX_EBITMAP_NODE_SIZE - sizeof(void *) - sizeof(u32)) /
                                sizeof(unsigned long),
};

struct ebitmap_node
{
    struct ebitmap_node *next;
    unsigned long maps[SELINUX_EBITMAP_UNIT_NUMS];
    u32 startbit;
};

struct ebitmap
{
    struct ebitmap_node *node;
    u32 highbit;
};

struct mls_level
{
    u32 sens;
    struct ebitmap cat;
};

struct mls_range
{
    struct mls_level level[2];
};

struct context
{
    u32 user;
    u32 role;
    u32 type;
    u32 len;
    struct mls_range range;
    char *str;
    u32 hash;
};

struct constraint_expr
{
    u32 expr_type;
    u32 attr;
    u32 op;
    struct ebitmap names;
    struct type_set *type_names;
    struct constraint_expr *next;
};

struct constraint_node
{
    u32 permissions;
    struct constraint_expr *expr;
    struct constraint_node *next;
};

struct common_datum
{
    u32 value;
    struct symtab permissions;
};

struct class_datum
{
    u32 value;
    char *comkey;
    struct common_datum *comdatum;
    struct symtab permissions;
    struct constraint_node *constraints;
    struct constraint_node *validatetrans;
    char default_user;
    char default_role;
    char default_type;
    char default_range;
};

struct role_datum
{
    u32 value;
    u32 bounds;
    struct ebitmap dominates;
    struct ebitmap types;
};

struct role_trans
{
    u32 role;
    u32 type;
    u32 tclass;
    u32 new_role;
    struct role_trans *next;
};

struct filename_trans
{
    u32 stype;
    u32 ttype;
    u16 tclass;
    const char *name;
};

struct role_allow
{
    u32 role;
    u32 new_role;
    struct role_allow *next;
};

struct type_datum
{
    u32 value;
    u32 bounds;
    unsigned char primary;
    unsigned char attribute;
};

struct user_datum
{
    u32 value;
    u32 bounds;
    struct ebitmap roles;
    struct mls_range range;
    struct mls_level dfltlevel;
};

struct level_datum
{
    struct mls_level *level;
    unsigned char isalias;
};

struct cat_datum
{
    u32 value;
    unsigned char isalias;
};

struct range_trans
{
    u32 source_type;
    u32 target_type;
    u32 target_class;
};

struct cond_bool_datum
{
    u32 value;
    int state;
};

struct cond_node;

struct type_set
{
    struct ebitmap types;
    struct ebitmap negset;
    u32 flags;
};

struct ocontext
{
    union
    {
        char *name;
        struct
        {
            u8 protocol;
            u16 low_port;
            u16 high_port;
        } port;
        struct
        {
            u32 addr;
            u32 mask;
        } node;
        struct
        {
            u32 addr[4];
            u32 mask[4];
        } node6;
        struct
        {
            u64 subnet_prefix;
            u16 low_pkey;
            u16 high_pkey;
        } ibpkey;
        struct
        {
            char *dev_name;
            u8 port;
        } ibendport;
    } u;
    union
    {
        u32 sclass;
        u32 behavior;
    } v;
    struct context context[2];
    u32 sid[2];
    struct ocontext *next;
};

struct genfs
{
    char *fstype;
    struct ocontext *head;
    struct genfs *next;
};

struct avtab_key
{
    u16 source_type;
    u16 target_type;
    u16 target_class;
    u16 specified;
};

#define AVTAB_ALLOWED 0x0001
#define AVTAB_AUDITALLOW 0x0002
#define AVTAB_AUDITDENY 0x0004
#define AVTAB_XPERMS_ALLOWED 0x0100
#define AVTAB_XPERMS_AUDITALLOW 0x0200
#define AVTAB_XPERMS_DONTAUDIT 0x0400

struct avtab_extended_perms
{
    u8 specified;
    u8 driver;
    struct extended_perms_data perms;
};

struct avtab_datum
{
    union
    {
        u32 data;
        struct avtab_extended_perms *xperms;
    } u;
};

struct avtab_node
{
    struct avtab_key key;
    struct avtab_datum datum;
    struct avtab_node *next;
};

struct avtab
{
    struct flex_array *htable;
    u32 nel;
    u32 nslot;
    u32 mask;
};

#define SYM_COMMONS 0
#define SYM_CLASSES 1
#define SYM_ROLES 2
#define SYM_TYPES 3
#define SYM_USERS 4
#define SYM_BOOLS 5
#define SYM_LEVELS 6
#define SYM_CATS 7
#define SYM_NUM 8
#define OCON_ISID 0
#define OCON_FS 1
#define OCON_PORT 2
#define OCON_NETIF 3
#define OCON_NODE 4
#define OCON_FSUSE 5
#define OCON_NODE6 6
#define OCON_IBPKEY 7
#define OCON_IBENDPORT 8
#define OCON_NUM 9

struct policydb
{
    int mls_enabled;
    int android_netlink_route;
    int android_netlink_getneigh;
    struct symtab symtab[SYM_NUM];
    struct flex_array *sym_val_to_name[SYM_NUM];
    struct class_datum **class_val_to_struct;
    struct role_datum **role_val_to_struct;
    struct user_datum **user_val_to_struct;
    struct flex_array *type_val_to_struct_array;
    struct avtab te_avtab;
    struct role_trans *role_tr;
    struct ebitmap filename_trans_ttypes;
    struct hashtab *filename_trans;
    struct cond_bool_datum **bool_val_to_struct;
    struct avtab te_cond_avtab;
    struct cond_node *cond_list;
    struct role_allow *role_allow;
    struct ocontext *ocontexts[OCON_NUM];
    struct genfs *genfs;
    struct hashtab *range_tr;
    struct flex_array *type_attr_map_array;
    struct ebitmap policycaps;
    struct ebitmap permissive_map;
    size_t len;
    unsigned int policyvers;
    unsigned int reject_unknown : 1;
    unsigned int allow_unknown : 1;
    u16 process_class;
    u32 process_trans_perms;
};

/* sidtab entry (only the leading fields are used: sid + context). */
struct sidtab_entry
{
    u32 sid;
    struct context context;
    struct hlist_node hash;
    struct sidtab_entry *next;
};

/* ---- vmalloc with the GKI *_noprof fallback ---- */

void *kp_vmalloc(unsigned long size)
{
    if (kfunc(vmalloc)) return kfunc(vmalloc)(size);
    if (kfunc(vmalloc_noprof)) return kfunc(vmalloc_noprof)(size);
    return NULL;
}

void kp_vfree(const void *addr)
{
    if (kfunc(vfree)) kfunc(vfree)(addr);
}

/* ---- resolved symbols ---- */

typedef int (*policydb_read_fn)(struct policydb *p, struct policy_file *fp);
typedef int (*policydb_load_isids_fn)(struct policydb *p, void *s);
typedef void (*policydb_destroy_fn)(struct policydb *p);
static policydb_read_fn kp_policydb_read;
static policydb_load_isids_fn kp_policydb_load_isids;
static policydb_destroy_fn kp_policydb_destroy;

/* 6.4+ ss/ internals used by the *_with_policy wrappers. */
typedef int (*string_to_context_struct_fn)(struct policydb *pol, void *sidtab, char *scontext,
                                           struct context *ctx, u32 def_sid);
typedef int (*sidtab_context_to_sid_fn)(void *s, struct context *context, u32 *out_sid);
typedef struct sidtab_entry *(*sidtab_search_entry_fn)(void *s, u32 sid);
typedef int (*sidtab_sid2str_get_fn)(void *s, struct sidtab_entry *entry, char **out, u32 *out_len);
typedef void (*sidtab_sid2str_put_fn)(void *s, struct sidtab_entry *entry, char *str, u32 str_len);
typedef int (*context_struct_to_string_fn)(struct policydb *p, struct context *context, char **scontext,
                                           u32 *scontext_len);
typedef struct sidtab_entry *(*sidtab_search_core_fn)(void *s, u32 sid, int force);
typedef void (*context_struct_compute_av_fn)(struct policydb *policydb, struct context *scontext,
                                             struct context *tcontext, u16 tclass, struct av_decision *avd,
                                             struct extended_perms *xperms);

static string_to_context_struct_fn kp_string_to_context_struct;
static sidtab_context_to_sid_fn kp_sidtab_context_to_sid;
static sidtab_search_entry_fn kp_sidtab_search_entry;
static sidtab_sid2str_get_fn kp_sidtab_sid2str_get;
static sidtab_sid2str_put_fn kp_sidtab_sid2str_put;
static context_struct_to_string_fn kp_context_struct_to_string;
static sidtab_search_core_fn kp_sidtab_search_core;
static context_struct_compute_av_fn kp_context_struct_compute_av;

/* ---- state ---- */

static bool g_backup_ready;
static void *g_backup_policy; /* our own struct selinux_policy-equivalent (heap) */

static bool selinux_sepolicy_supported(void)
{
    return kver >= KP_SEPOLICY_MIN_VERSION;
}

static struct policydb *kp_backup_policydb(void);
static void *kp_backup_sidtab(void);
int selinux_sepolicy_snapshot(void);
static int kp_context_to_sid_with_policy(const char *scontext, u32 scontext_len, u32 *out_sid, u32 def_sid,
                                         gfp_t gfp);
static int kp_sid_to_context_with_policy(u32 sid, char **scontext, u32 *scontext_len);
static void kp_compute_av_user_with_policy(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

/* ---- clean-eval scope (selinux_magisk_access_filter KPM mechanism) ----
 * While an app's /sys/fs/selinux/context or /access query is being answered
 * under this scope, context_struct_compute_av()/string_to_context_struct() get
 * their policydb argument redirected to the clean copy, so the kernel's own
 * lookup computes against the pre-root policy.  Task-keyed and synchronous: only
 * the task that entered the scope is redirected. */
static struct {
    void *task;
    u32 depth;
} clean_eval_scope = { NULL, 0 };

/* Task-keyed and synchronous: only the task that entered the scope is
 * redirected.  The slot is advisory — if another task holds it we just fall
 * back to the live policy, so no atomicity is required. */
static bool kp_clean_eval_enter(void)
{
    if (clean_eval_scope.task == current) {
        clean_eval_scope.depth++;
    } else if (!clean_eval_scope.task) {
        clean_eval_scope.task = current;
        clean_eval_scope.depth = 1;
    } else {
        return false;
    }
    return true;
}

static void kp_clean_eval_leave(void)
{
    if (clean_eval_scope.task == current) {
        if (clean_eval_scope.depth > 1) {
            clean_eval_scope.depth--;
        } else {
            clean_eval_scope.depth = 0;
            clean_eval_scope.task = NULL;
        }
    }
}

static bool kp_clean_eval_active(void)
{
    return clean_eval_scope.task == current && clean_eval_scope.depth;
}

int selinux_sepolicy_clean_eval_enter(void)
{
    return kp_clean_eval_enter() ? 0 : -EAGAIN;
}

void selinux_sepolicy_clean_eval_leave(void)
{
    kp_clean_eval_leave();
}

/* context_struct_compute_av(policydb, scontext, tcontext, tclass, avd, xperms):
 * the policydb argument is redirected to the clean copy while an app query is
 * being answered, so the kernel's own AV computation runs against the pre-root
 * policy. */
static void before_context_struct_compute_av(hook_fargs6_t *a, void *u)
{
    if (!kp_clean_eval_active() || !g_backup_ready) return;
    void *clean = kp_backup_policydb();
    if (!is_bad_address(clean)) {
        if (selinux_hide_query_log_level() >= 2)
            logkfi("query redirect compute_av: policydb %llx -> %llx\n", a->arg0, (unsigned long)clean);
        a->arg0 = (uint64_t)clean;
    }
}

/* string_to_context_struct(policydb, sidtab, scontext, ctx, def_sid): same
 * redirect so contextExists probes resolve against the clean snapshot. */
static void before_string_to_context_struct(hook_fargs5_t *a, void *u)
{
    if (kp_clean_eval_active() && g_backup_ready) {
        void *clean = kp_backup_policydb();
        if (!is_bad_address(clean)) {
            if (selinux_hide_query_log_level() >= 2)
                logkfi("query redirect string_to_context_struct: policydb %llx -> %llx\n", a->arg0,
                       (unsigned long)clean);
            a->arg0 = (uint64_t)clean;
        }
    }
}

/* ---- KernelSU-style deep copy of the clean policy ----
 * Mirror of KernelSU's ksu_dup_sepolicy(): the copy is fully independent, so
 * every pointer it holds belongs to it (that is what makes it a deep copy --
 * a struct copy would share the live policy's tables).  Steps:
 *   1. security_read_policy() serializes the (still stock) live policy; the
 *      policydb_write() hook in patch/android/sepolicy_flags.c has already
 *      fixed the AOSP android_netlink_route/getneigh config bits in the blob
 *      (KernelSU patches the same word by hand at offset 20).
 *   2. policydb_read() rebuilds a standalone policydb from the blob into a
 *      zeroed heap block laid out as
 *      struct selinux_policy { struct sidtab *sidtab; struct policydb; ... }.
 *   3. the serialized length is restored (KernelSU forces policydb.len too:
 *      the reparse can compute a different value).
 *   4. policydb_load_isids() populates our own sidtab with the initial SIDs, so
 *      sid <-> context queries answer from the copy (KernelSU gives
 *      backup_sepolicy a fresh sidtab the same way).
 *
 * Unlike security_load_policy() this starts no sidtab-conversion workqueue and
 * never touches the live policy, so it cannot wedge a workqueue pool.
 */

/* Snapshot cleanliness probe: the serialized policy is scanned for
 * root-manager artifacts.  The "clean" copy must be the boot policy, so if
 * these names are already present the snapshot was taken after the manager
 * reloaded the policy -- the feature would then be hiding nothing. */
static int kp_blob_count(const unsigned char *blob, size_t len, const char *needle)
{
    size_t n = lib_strlen(needle);
    int count = 0;

    if (!n || len < n) return 0;
    for (size_t i = 0; i + n <= len && count < 999; i++) {
        if (blob[i] == (unsigned char)needle[0] && lib_memcmp(blob + i, needle, n) == 0) count++;
    }
    return count;
}

/* Names that only appear in a policy once a root manager patched it (the same
 * set the on-device detectors probe for).  Explicit calls on purpose: an array
 * of string pointers inside kpimg is not relocated at load time, so its entries
 * would still hold link addresses and dereferencing them oopses. */
static bool kp_blob_is_clean(const void *blob, size_t len)
{
    int n;

    n = kp_blob_count(blob, len, "magisk");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'magisk' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "ksu");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'ksu' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "apatch");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'apatch' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "supolicy");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'supolicy' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "lsposed");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'lsposed' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "droidspaces");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'droidspaces' x%d\n", n);
        return false;
    }
    n = kp_blob_count(blob, len, "xposed");
    if (n) {
        log_boot("selinux_sepolicy: policy blob carries 'xposed' x%d\n", n);
        return false;
    }
    return true;
}

/* ---- policy-load capture ----
 *
 * Android loads the policy more than once: first-stage init loads the platform
 * policy, second-stage init the full one (vendor/odm included), and only then
 * do the root managers reload it with their patches.  Snapshotting at
 * post-fs-data can therefore copy an EARLIER epoch (e.g. the platform-only
 * policy, which lacks vendor types such as msd_daemon) -- an "oracle" detector
 * asks the policy about contexts the device must know, gets "unknown" and
 * concludes the policy was swapped.
 *
 * So instead of guessing a time, keep the last blob whose scan is clean and
 * stop replacing it once a marker-carrying load shows up: at boot that yields
 * the full platform policy, and the manager's later reload cannot overwrite it.
 */
static void *g_clean_blob;      /* last marker-free policy blob (as loaded) */
static size_t g_clean_blob_len;
static bool g_clean_locked;     /* a marker-carrying load was seen */

static void kp_capture_policy_load(uint64_t ret)
{
    void *data = NULL;
    size_t len = 0;
    void *copy;
    int rc;

    if ((int)ret != 0 || g_clean_locked) return;

    /* Never read the hooked function's arguments: security_load_policy's ABI
     * differs across versions and LTO can fold it (on 6.12-android16 arg0 is
     * not the blob pointer, and dereferencing it oopsed).  Serialize whatever
     * is active now instead -- right after a successful load that is exactly
     * the policy that was just installed. */
    if (!kfunc(security_read_policy)) {
        kfunc(security_read_policy) = (typeof(kfunc(security_read_policy)))lookup_name_with_suffix(
            "security_read_policy");
        if (!kfunc(security_read_policy)) return;
    }
    rc = security_read_policy(&data, &len);
    if (rc || !data || !len) {
        if (data && kfunc(kvfree)) kfunc(kvfree)(data);
        return;
    }

    if (!kp_blob_is_clean(data, len)) {
        g_clean_locked = true;
        log_boot("selinux_sepolicy: loaded policy len %zu carries root markers, keeping the %zu byte clean blob\n",
                 len, g_clean_blob_len);
    } else {
        copy = kp_vmalloc(len);
        if (copy) {
            lib_memcpy(copy, data, len);
            if (g_clean_blob) kp_vfree(g_clean_blob);
            g_clean_blob = copy;
            g_clean_blob_len = len;
            log_boot("selinux_sepolicy: captured clean policy blob from a load (len %zu)\n", len);
        }
    }
    if (kfunc(kvfree)) kfunc(kvfree)(data);
}

/* >= 6.4: only the return value is used, see above. */
static void after_security_load_policy_3(hook_fargs3_t *a, void *u)
{
    kp_capture_policy_load(a->ret);
}

/* < 6.4: same, ABI differences cannot hurt us. */
static void after_security_load_policy_4(hook_fargs4_t *a, void *u)
{
    kp_capture_policy_load(a->ret);
}

static bool g_load_hook_installed;

/* Idempotent: installed from the boot-time init so the platform policy loads
 * (first and second stage init) are seen; the post-fs-data init calls it too
 * in case the boot-time call could not resolve the symbol yet. */
static void kp_install_load_hook(void)
{
    unsigned long addr;

    if (g_load_hook_installed || !selinux_sepolicy_supported()) return;
    addr = lookup_name_with_suffix("security_load_policy");
    if (!addr) return;
    if (kver >= KP_SEPOLICY_WITH_POLICY_MIN_VERSION)
        hook_wrap3((void *)addr, NULL, after_security_load_policy_3, NULL);
    else
        hook_wrap4((void *)addr, NULL, after_security_load_policy_4, NULL);
    g_load_hook_installed = true;
    log_boot("selinux_sepolicy: hooked security_load_policy @ %llx\n", addr);
}

/* Called as early as possible (before_rest_init): the policy is loaded by
 * userspace init shortly after, so the capture hook must already be in place. */
int selinux_sepolicy_boot_init(void)
{
    if (!selinux_sepolicy_supported()) return -EOPNOTSUPP;
    kp_install_load_hook();
    return 0;
}

static void kp_log_blob_diag(const char *tag, const void *blob, size_t len)
{
    u32 vers = len >= 20 ? *(u32 *)((const char *)blob + 16) : 0;

    log_boot("selinux_sepolicy: %s scan (len %zu, vers %u)\n", tag, len, vers);
    log_boot("selinux_sepolicy:   device names: msd_daemon=%d msd_app=%d app_zygote=%d dex2oat=%d adbroot=%d\n",
             kp_blob_count(blob, len, "msd_daemon"), kp_blob_count(blob, len, "msd_app"),
             kp_blob_count(blob, len, "app_zygote"), kp_blob_count(blob, len, "dex2oat"),
             kp_blob_count(blob, len, "adbroot"));
    log_boot("selinux_sepolicy:   root names: magisk=%d ksu=%d apatch=%d lsposed=%d xposed=%d droidspaces=%d\n",
             kp_blob_count(blob, len, "magisk"), kp_blob_count(blob, len, "ksu"),
             kp_blob_count(blob, len, "apatch"), kp_blob_count(blob, len, "lsposed"),
             kp_blob_count(blob, len, "xposed"), kp_blob_count(blob, len, "droidspaces"));
}

static int kp_dup_sepolicy(void)
{
    struct policy_file fp;
    struct policydb *pdb;
    void *data = NULL;
    void *pol;
    void *sidtab;
    size_t len = 0;
    bool owned = false;
    int rc;

    if (!kfunc(security_read_policy) || !kp_policydb_read || !kp_policydb_load_isids) {
        log_boot("selinux_sepolicy: security_read_policy/policydb_read/policydb_load_isids not resolved\n");
        return -ENOENT;
    }

    if (g_clean_blob && g_clean_blob_len) {
        /* The load path captured the full platform policy before any manager
         * patched it: parse THAT, not whatever is live now. */
        data = g_clean_blob;
        len = g_clean_blob_len;
        log_boot("selinux_sepolicy: using the captured clean policy blob (%zu bytes)\n", len);
    } else {
        rc = security_read_policy(&data, &len);
        if (rc || !data || !len) {
            log_boot("selinux_sepolicy: security_read_policy failed rc=%d\n", rc);
            if (data && kfunc(kvfree)) kfunc(kvfree)(data);
            return rc ? rc : -EINVAL;
        }
        owned = true;
        /* No load was captured: this is whatever policy is live now, so report
         * whether it is still free of root markers. */
        log_boot("selinux_sepolicy: live blob scan (len %zu), clean=%d\n", len, kp_blob_is_clean(data, len));
    }

    /* policydb_read()/policydb_load_isids() require zero-initialized targets
     * with room for the real structs, which may be larger than the layouts we
     * declare below; hence the generous heap blocks. */
    pol = kp_vmalloc(KP_BACKUP_POLICY_SIZE);
    sidtab = kp_vmalloc(KP_BACKUP_SIDTAB_SIZE);
    if (!pol || !sidtab) {
        log_boot("selinux_sepolicy: copy allocation failed\n");
        rc = -ENOMEM;
        goto out_free;
    }
    lib_memset(pol, 0, KP_BACKUP_POLICY_SIZE);
    lib_memset(sidtab, 0, KP_BACKUP_SIDTAB_SIZE);

    pdb = (struct policydb *)((char *)pol + KP_POLICY_POLICYDB_OFFSET);
    fp.data = data;
    fp.len = len;
    rc = kp_policydb_read(pdb, &fp);
    if (rc) {
        log_boot("selinux_sepolicy: policydb_read failed rc=%d\n", rc);
        goto out_free;
    }
    pdb->len = len; /* KernelSU restores the serialized length after reparse */

    rc = kp_policydb_load_isids(pdb, sidtab);
    if (rc) {
        log_boot("selinux_sepolicy: policydb_load_isids failed rc=%d\n", rc);
        if (kp_policydb_destroy) kp_policydb_destroy(pdb);
        goto out_free;
    }

    *(void **)pol = sidtab; /* policy->sidtab @0 */
    g_backup_policy = pol;
    g_backup_ready = true;
    log_boot("selinux_sepolicy: deep copy ready (vers %u, len %zu, pdb %llx, sidtab %llx)\n",
             pdb->policyvers, pdb->len, (unsigned long)pdb, (unsigned long)sidtab);
    rc = 0;
    goto out;

out_free:
    if (pol) kp_vfree(pol);
    if (sidtab) kp_vfree(sidtab);
out:
    if (owned && data && kfunc(kvfree)) kfunc(kvfree)(data);
    return rc;
}

int selinux_sepolicy_snapshot(void)
{
    if (!selinux_sepolicy_supported()) return -EOPNOTSUPP;
    if (g_backup_ready) return 0;
    return kp_dup_sepolicy();
}

bool selinux_sepolicy_backup_ready(void)
{
    return g_backup_ready;
}

/* ---- query helpers against the deep copy ---- */

static struct policydb *kp_backup_policydb(void)
{
    if (is_bad_address(g_backup_policy)) return NULL;
    return (struct policydb *)((char *)g_backup_policy + KP_POLICY_POLICYDB_OFFSET);
}

static void *kp_backup_sidtab(void)
{
    if (is_bad_address(g_backup_policy)) return NULL;
    return *(void **)g_backup_policy;
}

/* ---- query helpers against the backup policy ---- */

static int kp_context_to_sid_with_policy(const char *scontext, u32 scontext_len, u32 *out_sid, u32 def_sid,
                                         gfp_t gfp)
{
    struct policydb *policydb = kp_backup_policydb();
    void *sidtab = kp_backup_sidtab();
    struct context context;
    char *scontext2;
    int rc;

    if (!policydb || !sidtab || !scontext_len) return -EINVAL;
    if (!kp_string_to_context_struct || !kp_sidtab_context_to_sid) return -ENOSYS;

    scontext2 = kp_vmalloc(scontext_len + 1);
    if (!scontext2) return -ENOMEM;
    lib_memcpy(scontext2, scontext, scontext_len);
    scontext2[scontext_len] = '\0';

    rc = kp_string_to_context_struct(policydb, sidtab, scontext2, &context, def_sid);
    if (rc) goto out;
    rc = kp_sidtab_context_to_sid(sidtab, &context, out_sid);
out:
    kp_vfree(scontext2);
    return rc;
}

static int kp_sid_to_context_with_policy(u32 sid, char **scontext, u32 *scontext_len)
{
    struct policydb *policydb = kp_backup_policydb();
    void *sidtab = kp_backup_sidtab();
    struct sidtab_entry *entry;
    int rc;

    if (scontext) *scontext = NULL;
    *scontext_len = 0;
    if (!policydb || !sidtab || !kp_sidtab_search_entry) return -EINVAL;

    entry = kp_sidtab_search_entry(sidtab, sid);
    if (!entry) return -EINVAL;

    if (kp_sidtab_sid2str_get) {
        rc = kp_sidtab_sid2str_get(sidtab, entry, scontext, scontext_len);
        if (rc != -ENOENT) return rc;
    }
    if (!kp_context_struct_to_string) return -EINVAL;
    rc = kp_context_struct_to_string(policydb, &entry->context, scontext, scontext_len);
    if (!rc && scontext && kp_sidtab_sid2str_put)
        kp_sidtab_sid2str_put(sidtab, entry, *scontext, *scontext_len);
    return rc;
}

static void kp_compute_av_user_with_policy(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
    struct policydb *policydb = kp_backup_policydb();
    void *sidtab = kp_backup_sidtab();
    struct sidtab_entry *se, *te;
    struct context *scontext, *tcontext;

    if (!policydb || !sidtab || !kp_context_struct_compute_av || !kp_sidtab_search_core) return;

    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    avd->seqno = KP_AVD_CLEAN_SEQNO;
    avd->flags = 0;

    se = kp_sidtab_search_core(sidtab, ssid, 0);
    if (!se) return;
    scontext = &se->context;

    te = kp_sidtab_search_core(sidtab, tsid, 0);
    if (!te) return;
    tcontext = &te->context;
    if (unlikely(!tclass)) return;

    kp_context_struct_compute_av(policydb, scontext, tcontext, tclass, avd, NULL);
}

/* ---- public query dispatch ----
 * All of them answer through the ss/ wrappers on top of the deep copy, so the
 * same code serves every supported kernel; a wrapper whose symbols did not
 * resolve reports -ENOSYS.  (The old fake selinux_state route is gone: a
 * zero-initialized fake state has no policy and would fault inside the kernel's
 * state-based helpers on every retrieval.) */

int selinux_sepolicy_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp)
{
    if (!g_backup_ready) return -ENOSYS;
    return kp_context_to_sid_with_policy(scontext, scontext_len, out_sid, SECSID_NULL, gfp);
}

int selinux_sepolicy_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
{
    if (!g_backup_ready) return -ENOSYS;
    return kp_sid_to_context_with_policy(sid, scontext, scontext_len);
}

int selinux_sepolicy_context_str_to_sid(const char *scontext, u32 *out_sid, gfp_t gfp)
{
    if (!g_backup_ready) return -ENOSYS;
    return kp_context_to_sid_with_policy(scontext, lib_strlen(scontext), out_sid, SECSID_NULL, gfp);
}

void selinux_sepolicy_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
    if (!g_backup_ready) return;
    kp_compute_av_user_with_policy(ssid, tsid, tclass, avd);
}

u32 selinux_sepolicy_clean_seq(void)
{
    if (kver >= VERSION(6, 7, 0)) return 4;
    return 0;
}

/* ---- init ---- */

int selinux_sepolicy_init(void)
{
    unsigned long addr;

    if (!selinux_sepolicy_supported()) {
        log_boot("selinux_sepolicy: requires kernel >= 4.19 (kver %x)\n", kver);
        return -EOPNOTSUPP;
    }

    /* ss/ internals used by the deep copy and the query wrappers: try the exact
     * kallsyms name first, then fall back to the suffix-tolerant lookup for
     * clang-LTO kernels that mangle static names to <name>.<n> /
     * <name>.llvm.<hash>. */
    kp_policydb_read = (policydb_read_fn)lookup_name_with_suffix("policydb_read");
    kp_policydb_load_isids = (policydb_load_isids_fn)lookup_name_with_suffix("policydb_load_isids");
    kp_policydb_destroy = (policydb_destroy_fn)lookup_name_with_suffix("policydb_destroy");

    kp_string_to_context_struct = (string_to_context_struct_fn)lookup_name_with_suffix("string_to_context_struct");
    kp_sidtab_context_to_sid = (sidtab_context_to_sid_fn)lookup_name_with_suffix("sidtab_context_to_sid");
    kp_sidtab_search_entry = (sidtab_search_entry_fn)lookup_name_with_suffix("sidtab_search_entry");
    kp_sidtab_sid2str_get = (sidtab_sid2str_get_fn)lookup_name_with_suffix("sidtab_sid2str_get");
    kp_sidtab_sid2str_put = (sidtab_sid2str_put_fn)lookup_name_with_suffix("sidtab_sid2str_put");
    kp_context_struct_to_string = (context_struct_to_string_fn)lookup_name_with_suffix("context_struct_to_string");
    kp_sidtab_search_core = (sidtab_search_core_fn)lookup_name_with_suffix("sidtab_search_core");
    kp_context_struct_compute_av = (context_struct_compute_av_fn)lookup_name_with_suffix("context_struct_compute_av");

    /* Only the argument-redirect hooks are needed: the deep copy is consumed by
     * swapping the policydb argument while an app query runs. */
    addr = lookup_name_with_suffix("context_struct_compute_av");
    if (addr) {
        hook_wrap6((void *)addr, before_context_struct_compute_av, NULL, NULL);
        log_boot("selinux_sepolicy: hooked context_struct_compute_av @ %llx\n", addr);
    }
    addr = lookup_name_with_suffix("string_to_context_struct");
    if (addr) {
        hook_wrap5((void *)addr, before_string_to_context_struct, NULL, NULL);
        log_boot("selinux_sepolicy: hooked string_to_context_struct @ %llx\n", addr);
    }

    /* Capture policy blobs as they are loaded, so the clean copy comes from the
     * full platform policy and not from an earlier (or later, patched) epoch.
     * ABI: >= 6.4 (data, len, load_state); before that
     * (state, data, len, load_state). */
    addr = lookup_name_with_suffix("security_load_policy");
    if (addr) {
        if (kver >= KP_SEPOLICY_WITH_POLICY_MIN_VERSION)
            hook_wrap3((void *)addr, NULL, after_security_load_policy_3, NULL);
        else
            hook_wrap4((void *)addr, NULL, after_security_load_policy_4, NULL);
        log_boot("selinux_sepolicy: hooked security_load_policy @ %llx\n", addr);
    }


    log_boot("selinux_sepolicy: read=%llx str2ctx=%llx sidtab2sid=%llx search=%llx\n",
             (unsigned long)kfunc(security_read_policy), (unsigned long)kp_string_to_context_struct,
             (unsigned long)kp_sidtab_context_to_sid, (unsigned long)kp_sidtab_search_entry);
    log_boot("selinux_sepolicy: sid2str=%llx ctx2str=%llx search_core=%llx compute_av=%llx\n",
             (unsigned long)kp_sidtab_sid2str_get, (unsigned long)kp_context_struct_to_string,
             (unsigned long)kp_sidtab_search_core, (unsigned long)kp_context_struct_compute_av);
    return 0;
}
