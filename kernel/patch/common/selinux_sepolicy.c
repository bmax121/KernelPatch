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
#include <asm/cmpxchg.h>
#include <uapi/asm-generic/errno.h>
#include <security/selinux/include/security.h>
#include <security/selinux/include/avc.h>
#include <kbtf.h>
#include <selinux_hide.h>

/* ---- constants ---- */

#define KP_POLICY_POLICYDB_OFFSET (sizeof(void *)) /* struct selinux_policy { sidtab*, policydb, ... } */
/* Heap allocations for the copy (KernelSU uses kmemdup/vmalloc the same way).
 * Generous margins: kernel code writes the structs at its own compiled offsets
 * and the real structs may be larger than the layouts declared below. */
#define KP_BACKUP_POLICY_SIZE 0x8000 /* standalone policydb + wrapper */
#define KP_BACKUP_SIDTAB_SIZE 0x4000 /* struct sidtab (hash roots etc.) */
#define KP_GFP_KERNEL 0xcc0u /* __GFP_RECLAIM | __GFP_IO | __GFP_FS */
#define KP_CONTEXT_PAYLOAD_LIMIT 4096

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

typedef void *(*kp_kmalloc_fn)(size_t, gfp_t);
typedef void (*kp_kfree_fn)(const void *);

static kp_kmalloc_fn kp_payload_kmalloc;
static kp_kfree_fn kp_payload_kfree;
static bool kp_payload_resolved;

static void kp_payload_resolve(void)
{
    if (kp_payload_resolved) return;
    kp_payload_resolved = true;

    kp_payload_kmalloc = (kp_kmalloc_fn)lookup_name_with_suffix("__kmalloc");
    if (!kp_payload_kmalloc) kp_payload_kmalloc = (kp_kmalloc_fn)lookup_name_with_suffix("__kmalloc_noprof");
    if (!kp_payload_kmalloc) kp_payload_kmalloc = (kp_kmalloc_fn)lookup_name_with_suffix("kmalloc");
    kp_payload_kfree = (kp_kfree_fn)lookup_name_with_suffix("kfree");
    log_boot("selinux_sepolicy: payload allocator: %s, free: %s\n",
             kp_payload_kmalloc ? "kmalloc" : "vmalloc", kp_payload_kfree ? "kfree" : "none");
}

static void *kp_payload_alloc(size_t size, gfp_t gfp, bool *via_vmalloc)
{
    kp_payload_resolve();
    if (kp_payload_kmalloc && kp_payload_kfree) {
        *via_vmalloc = false;
        return kp_payload_kmalloc(size, gfp);
    }
    *via_vmalloc = true;
    return kp_vmalloc(size);
}

static void kp_payload_free(void *p, bool via_vmalloc)
{
    if (!p) return;
    if (via_vmalloc) kp_vfree(p);
    else if (kp_payload_kfree) kp_payload_kfree(p);
}

void *kp_kernel_alloc(size_t size, gfp_t gfp, bool *via_vmalloc)
{
    return kp_payload_alloc(size, gfp, via_vmalloc);
}

void kp_kernel_free(void *p, bool via_vmalloc)
{
    kp_payload_free(p, via_vmalloc);
}

void kp_kernel_str_free(void *p)
{
    static bool warned;

    if (!p) return;
    kp_payload_resolve();
    if (kp_payload_kfree) {
        kp_payload_kfree(p);
        return;
    }
    if (!warned) {
        warned = true;
        logkfw("selinux_sepolicy: kfree unresolved, kernel strings cannot be released\n");
    }
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
/* Set once the snapshot's symbol tables have been reshaped to the live policy;
 * a later live reload makes that shape stale (logged once). */
static bool g_shadow_built;
static bool g_shadow_stale;
/* The setprocattr fast path depends on string_to_context_struct being
 * redirected inside the clean-eval scope; never take it if the hook failed. */
static bool g_string_redirect_installed;
static void *g_backup_policy; /* our own struct selinux_policy-equivalent (heap) */
static bool g_backup_allow_unknown;

static bool selinux_sepolicy_supported(void)
{
    return selinux_hide_is_supported();
}

static struct policydb *kp_backup_policydb(void);
static void *kp_backup_sidtab(void);
int selinux_sepolicy_snapshot(void);
static int kp_context_to_sid_with_policy(const char *scontext, u32 scontext_len, u32 *out_sid, u32 def_sid,
                                         gfp_t gfp);
static int kp_sid_to_context_with_policy(u32 sid, char **scontext, u32 *scontext_len);
static void kp_compute_av_user_with_policy(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

#define KP_CLEAN_EVAL_SLOTS 8

static struct {
    void *task;
    u32 depth;
} clean_eval_slots[KP_CLEAN_EVAL_SLOTS];

/* Non-zero while a task holds a slot.  before_context_struct_compute_av() runs
 * for every context in the system -- every AVC miss, hidden or not -- so its
 * idle path has to be one load and a branch, not a walk of the slot array.  The
 * counter is touched only when a scope is really entered or left, and it sits
 * on its own cache line so the two hot hooks never share one with the slots a
 * scope writes. */
static int kp_clean_eval_users __attribute__((aligned(64)));

static inline bool kp_clean_eval_idle(void)
{
    return __atomic_load_n(&kp_clean_eval_users, __ATOMIC_ACQUIRE) == 0;
}

/* Keep the counter a cmpxchg loop: a 32-bit add would be outlined into
 * __aarch64_ldadd4_rel, which this freestanding image does not link. */
static void kp_clean_eval_users_add(int delta)
{
    int old, new;

    do {
        old = __atomic_load_n(&kp_clean_eval_users, __ATOMIC_RELAXED);
        new = old + delta;
    } while (cmpxchg(&kp_clean_eval_users, old, new) != old);
}

static bool kp_clean_eval_enter(void)
{
    int i;

    for (i = 0; i < KP_CLEAN_EVAL_SLOTS; i++) {
        if (__atomic_load_n(&clean_eval_slots[i].task, __ATOMIC_ACQUIRE) == current) {
            clean_eval_slots[i].depth++;
            return true;
        }
    }
    for (i = 0; i < KP_CLEAN_EVAL_SLOTS; i++) {
        if (cmpxchg(&clean_eval_slots[i].task, NULL, current) == NULL) {
            clean_eval_slots[i].depth = 1;
            kp_clean_eval_users_add(1);
            return true;
        }
    }
    return false;
}

static void kp_clean_eval_leave(void)
{
    int i;

    for (i = 0; i < KP_CLEAN_EVAL_SLOTS; i++) {
        if (__atomic_load_n(&clean_eval_slots[i].task, __ATOMIC_ACQUIRE) != current) continue;
        if (clean_eval_slots[i].depth > 1) {
            clean_eval_slots[i].depth--;
        } else {
            clean_eval_slots[i].depth = 0;
            __atomic_store_n(&clean_eval_slots[i].task, NULL, __ATOMIC_RELEASE);
            kp_clean_eval_users_add(-1);
        }
        return;
    }
}

static bool kp_clean_eval_active(void)
{
    int i;

    if (kp_clean_eval_idle()) return false;
    for (i = 0; i < KP_CLEAN_EVAL_SLOTS; i++) {
        if (__atomic_load_n(&clean_eval_slots[i].task, __ATOMIC_ACQUIRE) == current &&
            clean_eval_slots[i].depth)
            return true;
    }
    return false;
}

int selinux_sepolicy_clean_eval_enter(void)
{
    return kp_clean_eval_enter() ? 0 : -EAGAIN;
}

void selinux_sepolicy_clean_eval_leave(void)
{
    kp_clean_eval_leave();
}

static void before_context_struct_compute_av(hook_fargs6_t *a, void *u)
{
    /* One load for the whole system: this runs on every AVC miss. */
    if (!g_backup_ready || kp_clean_eval_idle()) return;
    if (!kp_clean_eval_active()) return;
    {
        void *clean = kp_backup_policydb();

        if (!is_bad_address(clean)) {
            if (selinux_hide_query_log_level() >= 2)
                logkfi("query redirect compute_av: policydb %llx -> %llx\n", a->arg0, (unsigned long)clean);
            a->arg0 = (uint64_t)clean;
        }
    }
}

/* string_to_context_struct(policydb, sidtab, scontext, ctx, def_sid): same
 * redirect so contextExists probes resolve against the clean snapshot. */
static void before_string_to_context_struct(hook_fargs5_t *a, void *u)
{
    if (!g_backup_ready || kp_clean_eval_idle()) return;
    if (!kp_clean_eval_active()) return;
    {
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

typedef int (*security_read_policy_compat_fn)(void *state, void **data, size_t *len);

static security_read_policy_compat_fn kp_security_read_policy_compat;
static unsigned long kp_sepolicy_state_addr;
static bool kp_sepolicy_read_logged;

static int kp_sepolicy_read(void **data, size_t *len)
{
    bool without_state = selinux_hide_is_without_sepolicy_state_version();

    if (!kfunc(security_read_policy)) {
        kfunc(security_read_policy) = (typeof(kfunc(security_read_policy)))lookup_name_with_suffix(
            "security_read_policy");
        if (!kfunc(security_read_policy)) return -ENOENT;
    }

    if (!kp_sepolicy_read_logged) {
        kp_sepolicy_read_logged = true;
        log_boot("selinux_sepolicy: security_read_policy: %s ABI (kver %x)\n",
                 without_state ? "plain 2-arg" : "state 3-arg", kver);
    }

    if (without_state) return kfunc(security_read_policy)(data, len);

    if (!kp_sepolicy_state_addr) kp_sepolicy_state_addr = lookup_name_with_suffix("selinux_state");
    if (!kp_sepolicy_state_addr) {
        logkfw("selinux_sepolicy: selinux_state not found, the policy cannot be serialized\n");
        return -ENOENT;
    }
    if (!kp_security_read_policy_compat)
        kp_security_read_policy_compat = (security_read_policy_compat_fn)(uintptr_t)kfunc(security_read_policy);
    return kp_security_read_policy_compat((void *)kp_sepolicy_state_addr, data, len);
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

static void kp_log_blob_diag(const char *tag, const void *blob, size_t len);

#define KP_POLICYDB_MAGIC 0xf97cff8cU

static bool kp_blob_looks_valid(const void *blob, size_t len)
{
    u32 magic = 0;

    if (!blob || len < 4096 || len > (16u << 20)) return false;
    lib_memcpy(&magic, blob, sizeof(magic));
    return magic == KP_POLICYDB_MAGIC;
}

static bool kp_blob_config_word(const void *blob, size_t len, u32 *config)
{
    u32 magic = 0, slen = 0;
    size_t off;

    if (!blob || !config || len < 32) return false;
    lib_memcpy(&magic, blob, sizeof(magic));
    if (magic != KP_POLICYDB_MAGIC) return false;
    lib_memcpy(&slen, (const char *)blob + 4, sizeof(slen));
    if (!slen || slen > 64) return false;
    off = 8 + (size_t)slen + sizeof(u32);
    if (off + sizeof(u32) > len) return false;
    lib_memcpy(config, (const char *)blob + off, sizeof(*config));
    return true;
}

static void kp_capture_policy_load(uint64_t ret)
{
    void *data = NULL;
    size_t len = 0;
    void *copy;
    int rc;

    if ((int)ret != 0 || g_clean_locked) return;

    if (g_shadow_built && !g_shadow_stale) {
        g_shadow_stale = true;
        logkfw("selinux_sepolicy: live policy reloaded after the shadow, timing hardening is stale\n");
    }

    /* Never read the hooked function's arguments: security_load_policy's ABI
     * differs across versions and LTO can fold it (on 6.12-android16 arg0 is
     * not the blob pointer, and dereferencing it oopsed).  Serialize whatever
     * is active now instead -- right after a successful load that is exactly
     * the policy that was just installed. */
    rc = kp_sepolicy_read(&data, &len);
    if (rc == -ENOENT) return;
    if (rc || !data || !len) {
        if (data && kfunc(kvfree)) kfunc(kvfree)(data);
        return;
    }
    if (!kp_blob_looks_valid(data, len)) {
        logkfw("selinux_sepolicy: serialized policy rejected (len %zu), ignoring this load\n", len);
        if (kfunc(kvfree)) kfunc(kvfree)(data);
        return;
    }

    if (!kp_blob_is_clean(data, len)) {
        g_clean_locked = true;
        log_boot("selinux_sepolicy: loaded policy len %zu carries root markers, keeping the %zu byte clean blob\n",
                 len, g_clean_blob_len);
        kp_log_blob_diag("rejected", data, len);
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
    if (selinux_hide_is_without_sepolicy_state_version())
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

static bool g_snapshot_dirty;

static void kp_probe_one(const char *ctx, int *hits)
{
    u32 sid = 0;
    int rc = kp_context_to_sid_with_policy(ctx, lib_strlen(ctx), &sid, SECSID_NULL, KP_GFP_KERNEL);

    if (!rc) {
        (*hits)++;
        logkfw("selinux_sepolicy: snapshot resolves %s -> sid %u; it already carries a manager "
               "domain, hiding it is ineffective\n",
               ctx, sid);
    }
}

static void kp_probe_snapshot_domains(void)
{
    int hits = 0;

    if (!g_backup_ready) return;
    kp_probe_one("u:r:su:s0", &hits);
    kp_probe_one("u:r:ksu:s0", &hits);
    kp_probe_one("u:r:magisk:s0", &hits);
    kp_probe_one("u:r:lsposed:s0", &hits);
    if (hits)
        g_snapshot_dirty = true;
    else
        log_boot("selinux_sepolicy: snapshot answers no manager domain (clean)\n");
}

bool selinux_sepolicy_snapshot_dirty(void)
{
    return g_snapshot_dirty;
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
        rc = kp_sepolicy_read(&data, &len);
        if (rc || !data || !len) {
            log_boot("selinux_sepolicy: security_read_policy failed rc=%d\n", rc);
            if (data && kfunc(kvfree)) kfunc(kvfree)(data);
            return rc ? rc : -EINVAL;
        }
        if (!kp_blob_looks_valid(data, len)) {
            logkfw("selinux_sepolicy: serialized policy rejected (len %zu), no snapshot\n", len);
            if (kfunc(kvfree)) kfunc(kvfree)(data);
            return -EINVAL;
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

    {
        u32 config = 0;

        if (kp_blob_config_word(data, len, &config))
            g_backup_allow_unknown = (config & 0x4) != 0;
        else
            logkfw("selinux_sepolicy: policy header unparsable, assuming deny_unknown\n");
    }

    rc = kp_policydb_load_isids(pdb, sidtab);
    if (rc) {
        log_boot("selinux_sepolicy: policydb_load_isids failed rc=%d\n", rc);
        if (kp_policydb_destroy) kp_policydb_destroy(pdb);
        goto out_free;
    }

    *(void **)pol = sidtab; /* policy->sidtab @0 */
    g_backup_policy = pol;
    g_backup_ready = true;
    log_boot("selinux_sepolicy: deep copy ready (blob len %zu, allow_unknown %d, pdb %llx, sidtab %llx)\n",
             len, g_backup_allow_unknown, (unsigned long)pdb, (unsigned long)sidtab);
    kp_probe_snapshot_domains();
    rc = 0;
    goto out;

out_free:
    if (pol) kp_vfree(pol);
    if (sidtab) kp_vfree(sidtab);
out:
    if (owned && data && kfunc(kvfree)) kfunc(kvfree)(data);
    return rc;
}

/* ---- policy layout / shape diagnostics ----
 *
 * The SELinux symbol tables are hash tables whose size is roundup_pow_of_two(nel)
 * and whose lookup cost is the bucket chain length.  The clean snapshot and the
 * live policy can have different type counts, so an invalid-context query can
 * take a different amount of time depending on which policy answered.  This
 * logs the shape of both so a timing probe can be correlated with it.
 */
struct kp_policy_layout {
    bool ready;
    long policydb_symtab;
    long policydb_sym_val_to_name;
    long symtab_size;
    long symtab_table; /* offset of the embedded struct hashtab */
    long symtab_nprim;
    long hashtab_htable;
    long hashtab_size;
    long hashtab_nel;
    long node_key;
    long node_datum;
    long node_next;
    long state_policy;
    long state_policy_mutex;
    long selpolicy_policydb;
    long selpolicy_sidtab;
};

static struct kp_policy_layout g_pol_layout;

static void kp_policy_layout_init(void)
{
    long v;

    if (g_pol_layout.ready) return;
    g_pol_layout.ready = true;

    g_pol_layout.policydb_symtab = -1;
    g_pol_layout.policydb_sym_val_to_name = -1;
    g_pol_layout.symtab_size = -1;
    g_pol_layout.symtab_table = -1;
    g_pol_layout.symtab_nprim = -1;
    g_pol_layout.hashtab_htable = -1;
    g_pol_layout.hashtab_size = -1;
    g_pol_layout.hashtab_nel = -1;
    g_pol_layout.node_key = -1;
    g_pol_layout.node_datum = -1;
    g_pol_layout.node_next = -1;
    g_pol_layout.state_policy = -1;
    g_pol_layout.state_policy_mutex = -1;
    g_pol_layout.selpolicy_policydb = -1;
    g_pol_layout.selpolicy_sidtab = -1;

    /* BTF is required: struct selinux_state/selinux_policy/policydb are
     * __randomize_layout and their leading fields depend on config.  GKI
     * kernels ship BTF; without it the shadow is simply disabled. */
    if (!kp_btf_available()) {
        log_boot("selinux_sepolicy: layout: BTF unavailable, shadow disabled\n");
        return;
    }

    /* The embedded struct symtab + policydb.symtab[] layout arrived in 5.8 and
     * symtab_insert/symtab_search in 5.9; kp_shadow_resolve() requires those
     * symbols, so older kernels skip the shadow even if the layout probes. */
    if ((v = kp_btf_member_offset("policydb", "symtab")) >= 0) g_pol_layout.policydb_symtab = v;
    if ((v = kp_btf_member_offset("policydb", "sym_val_to_name")) >= 0)
        g_pol_layout.policydb_sym_val_to_name = v;
    if ((v = kp_btf_type_size("symtab")) > 0) g_pol_layout.symtab_size = v;
    if ((v = kp_btf_member_offset("symtab", "table")) >= 0) g_pol_layout.symtab_table = v;
    if ((v = kp_btf_member_offset("symtab", "nprim")) >= 0) g_pol_layout.symtab_nprim = v;
    if ((v = kp_btf_member_offset("hashtab", "htable")) >= 0) g_pol_layout.hashtab_htable = v;
    if ((v = kp_btf_member_offset("hashtab", "size")) >= 0) g_pol_layout.hashtab_size = v;
    if ((v = kp_btf_member_offset("hashtab", "nel")) >= 0) g_pol_layout.hashtab_nel = v;
    if ((v = kp_btf_member_offset("hashtab_node", "key")) >= 0) g_pol_layout.node_key = v;
    if ((v = kp_btf_member_offset("hashtab_node", "datum")) >= 0) g_pol_layout.node_datum = v;
    if ((v = kp_btf_member_offset("hashtab_node", "next")) >= 0) g_pol_layout.node_next = v;
    if ((v = kp_btf_member_offset("selinux_state", "policy")) >= 0) g_pol_layout.state_policy = v;
    if ((v = kp_btf_member_offset("selinux_state", "policy_mutex")) >= 0) g_pol_layout.state_policy_mutex = v;
    if ((v = kp_btf_member_offset("selinux_policy", "policydb")) >= 0) g_pol_layout.selpolicy_policydb = v;
    if ((v = kp_btf_member_offset("selinux_policy", "sidtab")) >= 0) g_pol_layout.selpolicy_sidtab = v;

    /* Bounds: the code stores a struct symtab in u64[4] and a struct hashtab
     * in u64[2], and walks hashtab_node fields.  Reject anything that would
     * not fit instead of trusting a future layout blindly. */
    if (g_pol_layout.policydb_symtab < 0 ||
        g_pol_layout.symtab_size <= 0 || g_pol_layout.symtab_size > 32 ||
        g_pol_layout.symtab_table < 0 ||
        g_pol_layout.symtab_nprim < 0 || g_pol_layout.symtab_nprim + 4 > g_pol_layout.symtab_size ||
        g_pol_layout.hashtab_htable < 0 || g_pol_layout.hashtab_htable + 8 > g_pol_layout.symtab_size ||
        g_pol_layout.hashtab_size < 0 || g_pol_layout.hashtab_size + 4 > g_pol_layout.symtab_size ||
        g_pol_layout.hashtab_nel < 0 || g_pol_layout.hashtab_nel + 4 > g_pol_layout.symtab_size ||
        g_pol_layout.node_key < 0 || g_pol_layout.node_datum < 0 ||
        g_pol_layout.node_next < 0 || g_pol_layout.node_next + 8 > 64 ||
        g_pol_layout.state_policy < 0 || g_pol_layout.state_policy_mutex < 0 ||
        g_pol_layout.selpolicy_policydb < 0) {
        logkfw("selinux_sepolicy: layout: incomplete/out-of-range BTF, shadow disabled\n");
        g_pol_layout.policydb_symtab = -1;
    }
}

static u32 kp_symhash(const char *key)
{
    u32 val = 0;
    const char *p = key;

    for (; *p; p++)
        val = ((val << 4) | (val >> 28)) ^ (u8)*p;
    return val;
}

#define KP_PROBE_A "u:r:selinux_hide_probe_invalid:s0"
#define KP_PROBE_B "\n:r:selinux_hide_probe_invalid:s0"

/* sym: 0 commons, 1 classes, 2 roles, 3 types, 4 users, 5 bools, 6 levels, 7 cats */
static void kp_log_symtab_shape(const char *tag, void *pdb, int sym, const char *label, const char *probe)
{
    char *base, *ht;
    u32 nprim, size, nel, bucket = 0, chain = 0;
    void **htable;

    if (!pdb || g_pol_layout.policydb_symtab < 0 || g_pol_layout.symtab_table < 0) return;

    base = (char *)pdb + g_pol_layout.policydb_symtab + (long)sym * g_pol_layout.symtab_size;
    nprim = *(u32 *)(base + g_pol_layout.symtab_nprim);
    ht = base + g_pol_layout.symtab_table;
    size = *(u32 *)(ht + g_pol_layout.hashtab_size);
    nel = *(u32 *)(ht + g_pol_layout.hashtab_nel);
    htable = *(void ***)(ht + g_pol_layout.hashtab_htable);
    if (htable && size) {
        void *node;
        bucket = kp_symhash(probe) & (size - 1);
        for (node = htable[bucket]; node; node = *(void **)((char *)node + g_pol_layout.node_next))
            chain++;
    }
    log_boot("selinux_sepolicy: %s %s nprim=%u size=%u nel=%u bucket=%u chain=%u\n",
             tag, label, nprim, size, nel, bucket, chain);
}

typedef void (*kp_mutex_fn)(void *);

static void kp_log_live_policy_shapes(void)
{
    unsigned long state = lookup_name_with_suffix("selinux_state");
    kp_mutex_fn lock = (kp_mutex_fn)(uintptr_t)lookup_name_with_suffix("mutex_lock");
    kp_mutex_fn unlock = (kp_mutex_fn)(uintptr_t)lookup_name_with_suffix("mutex_unlock");
    void *policy, *pdb = NULL;

    if (!state || g_pol_layout.policydb_symtab < 0) {
        log_boot("selinux_sepolicy: live shape: layout unavailable\n");
        return;
    }
    if (!lock || !unlock) {
        log_boot("selinux_sepolicy: live shape: mutex symbols unavailable\n");
        return;
    }
    lock((void *)(state + g_pol_layout.state_policy_mutex));
    policy = *(void **)(state + g_pol_layout.state_policy);
    if (policy && !is_bad_address(policy))
        pdb = (char *)policy + g_pol_layout.selpolicy_policydb;
    kp_log_symtab_shape("live", pdb, 4, "users", KP_PROBE_B);
    kp_log_symtab_shape("live", pdb, 2, "roles", KP_PROBE_A);
    kp_log_symtab_shape("live", pdb, 3, "types", KP_PROBE_A);
    unlock((void *)(state + g_pol_layout.state_policy_mutex));
}

static void kp_log_policy_shapes(void)
{
    void *clean;

    kp_policy_layout_init();
    if (g_pol_layout.policydb_symtab < 0) {
        log_boot("selinux_sepolicy: shape diagnostics skipped (layout unavailable)\n");
        return;
    }
    clean = kp_backup_policydb();
    kp_log_symtab_shape("clean", clean, 4, "users", KP_PROBE_B);
    kp_log_symtab_shape("clean", clean, 2, "roles", KP_PROBE_A);
    kp_log_symtab_shape("clean", clean, 3, "types", KP_PROBE_A);
    /* The live shape is logged at enable time: at "before" the manager may not
     * have reloaded the policy yet, so it would just repeat the clean shape. */
}

/* ---- live-shape shadow symbol tables ----
 *
 * The clean snapshot is a separate policydb, so its hash tables have the clean
 * type/role/user counts while the live manager-patched policy has more entries.
 * hashtab_search() walks the bucket in ascending strcmp order and breaks on the
 * first key greater than the probe, so an invalid context costs a different
 * number of comparisons depending on which policy answered.  That is the A/B
 * timing channel.
 *
 * Rebuild each parsed symtab (types, roles, users) with the LIVE key set, the
 * LIVE bucket size and therefore the LIVE sorted order.  Keys the clean policy
 * knows keep their clean datum; keys the live policy added are inserted with a
 * NULL datum, so string_to_context_struct exits at the same "!datum" check as
 * a genuinely unknown name, while the comparisons (count and keys) are exactly
 * those of the live policy for every probe.  policydb_destroy's destroy_f[]
 * guard `if (datum)` and kfree() it, so a NULL datum is safe at unload.
 *
 * The snapshot is private until the hooks are installed, so no RCU
 * publication is needed; the build runs once at enable (post-fs-data "after"),
 * after the manager has reloaded the policy and before the query hooks go in.
 */
typedef int (*kp_hashtab_init_fn)(void *h, u32 nel_hint);
typedef int (*kp_symtab_insert_fn)(void *s, char *name, void *datum);
typedef void *(*kp_symtab_search_fn)(void *s, const char *name);
typedef void (*kp_hashtab_destroy_fn)(void *h);
typedef char *(*kp_kstrdup_fn)(const char *s, gfp_t gfp);
typedef void (*kp_kfree_fn)(const void *p);

static kp_hashtab_init_fn kp_sh_hashtab_init;
static kp_symtab_insert_fn kp_sh_symtab_insert;
static kp_symtab_search_fn kp_sh_symtab_search;
static kp_hashtab_destroy_fn kp_sh_hashtab_destroy;
static kp_kstrdup_fn kp_sh_kstrdup;
static kp_kfree_fn kp_sh_kfree;
static bool kp_shadow_resolved;

static bool kp_shadow_resolve(void)
{
    if (kp_shadow_resolved) return true;
    kp_shadow_resolved = true;
    kp_sh_hashtab_init = (kp_hashtab_init_fn)(uintptr_t)lookup_name_with_suffix("hashtab_init");
    kp_sh_symtab_insert = (kp_symtab_insert_fn)(uintptr_t)lookup_name_with_suffix("symtab_insert");
    kp_sh_symtab_search = (kp_symtab_search_fn)(uintptr_t)lookup_name_with_suffix("symtab_search");
    kp_sh_hashtab_destroy = (kp_hashtab_destroy_fn)(uintptr_t)lookup_name_with_suffix("hashtab_destroy");
    kp_sh_kstrdup = (kp_kstrdup_fn)(uintptr_t)lookup_name_with_suffix("kstrdup");
    kp_sh_kfree = (kp_kfree_fn)(uintptr_t)lookup_name_with_suffix("kfree");
    if (!kp_sh_hashtab_init || !kp_sh_symtab_insert || !kp_sh_symtab_search ||
        !kp_sh_hashtab_destroy || !kp_sh_kstrdup || !kp_sh_kfree) {
        logkfw("selinux_sepolicy: shadow: symbols missing (init=%d insert=%d search=%d destroy=%d strdup=%d free=%d)\n",
               !!kp_sh_hashtab_init, !!kp_sh_symtab_insert, !!kp_sh_symtab_search,
               !!kp_sh_hashtab_destroy, !!kp_sh_kstrdup, !!kp_sh_kfree);
        return false;
    }
    return true;
}

struct kp_symtab_view {
    u32 size;
    u32 nel;
    u32 nprim;
    void **htable;
};

static void kp_symtab_view(void *base, struct kp_symtab_view *v)
{
    lib_memset(v, 0, sizeof(*v));
    if (!base) return;
    v->size = *(u32 *)((char *)base + g_pol_layout.hashtab_size);
    v->nel = *(u32 *)((char *)base + g_pol_layout.hashtab_nel);
    v->nprim = *(u32 *)((char *)base + g_pol_layout.symtab_nprim);
    v->htable = *(void ***)((char *)base + g_pol_layout.hashtab_htable);
}

static void *kp_clean_find(struct kp_symtab_view *cv, const char *key, char **key_out, void **datum_out)
{
    u32 bucket;
    void *node;

    if (!cv->htable || !cv->size) return NULL;
    bucket = kp_symhash(key) & (cv->size - 1);
    for (node = cv->htable[bucket]; node; node = *(void **)((char *)node + g_pol_layout.node_next)) {
        char *k = *(char **)((char *)node + g_pol_layout.node_key);
        if (k && !lib_strcmp(k, key)) {
            if (key_out) *key_out = k;
            if (datum_out) *datum_out = *(void **)((char *)node + g_pol_layout.node_datum);
            return node;
        }
    }
    return NULL;
}

/* Returns 0 on success, negative on failure.  Keys live-added with a NULL
 * datum are tracked so a failed build can release them. */
#define KP_SHADOW_MAX_HIDDEN 256

static int kp_shadow_one_symtab(void *clean_base, void *live_base, const char *label)
{
    struct kp_symtab_view cv, lv;
    u64 tmp[4];
    char *hidden_keys[KP_SHADOW_MAX_HIDDEN];
    u32 i, tmp_size, tmp_nel, hidden = 0, kept = 0, hidden_cnt = 0;
    void **tmp_htable;
    void *node;
    int rc;

    kp_symtab_view(clean_base, &cv);
    kp_symtab_view(live_base, &lv);
    if (!lv.htable || !lv.size) return 0;

    lib_memset(tmp, 0, sizeof(tmp));
    rc = kp_sh_hashtab_init(tmp, lv.size); /* size is already a power of two */
    if (rc) return rc;
    *(u32 *)((char *)tmp + g_pol_layout.symtab_nprim) = cv.nprim;

    for (i = 0; i < lv.size; i++) {
        for (node = lv.htable[i]; node; node = *(void **)((char *)node + g_pol_layout.node_next)) {
            char *live_key = *(char **)((char *)node + g_pol_layout.node_key);
            char *clean_key = NULL;
            void *clean_datum = NULL;
            char *key;
            void *datum;

            if (!live_key) continue;
            /* Membership with the kernel's own hash; kp_clean_find only fetches
             * the reusable clean key pointer.  If they disagree, the local
             * symhash is not the kernel's: abort instead of turning every
             * clean name into a NULL-datum hidden key. */
            if (kp_sh_symtab_search(clean_base, live_key)) {
                if (!kp_clean_find(&cv, live_key, &clean_key, &clean_datum)) {
                    logkfw("selinux_sepolicy: shadow %s: symhash mismatch on %s\n", label, live_key);
                    rc = -EINVAL;
                    goto out;
                }
                key = clean_key;
                datum = clean_datum;
            } else {
                if (kp_clean_find(&cv, live_key, &clean_key, &clean_datum)) {
                    logkfw("selinux_sepolicy: shadow %s: symhash mismatch (find hit, search miss) on %s\n",
                           label, live_key);
                    rc = -EINVAL;
                    goto out;
                }
                key = kp_sh_kstrdup(live_key, KP_GFP_KERNEL);
                if (!key) { rc = -ENOMEM; goto out; }
                datum = NULL; /* unknown at the parser's !datum check */
                if (hidden_cnt < KP_SHADOW_MAX_HIDDEN)
                    hidden_keys[hidden_cnt++] = key;
                hidden++;
            }
            rc = kp_sh_symtab_insert(tmp, key, datum);
            if (rc == -EEXIST) { rc = 0; continue; }
            if (rc) goto out;
        }
    }

    /* A clean name the live policy no longer has: keep it for correctness.
     * NULL-datum entries are keys a previous shadow injected, not clean names. */
    for (i = 0; i < cv.size; i++) {
        for (node = cv.htable[i]; node; node = *(void **)((char *)node + g_pol_layout.node_next)) {
            char *clean_key = *(char **)((char *)node + g_pol_layout.node_key);
            void *clean_datum = *(void **)((char *)node + g_pol_layout.node_datum);

            if (!clean_key || !clean_datum) continue;
            if (!kp_sh_symtab_search(tmp, clean_key)) {
                rc = kp_sh_symtab_insert(tmp, clean_key, clean_datum);
                if (rc == -EEXIST) { rc = 0; continue; }
                if (rc) goto out;
                kept++;
            }
        }
    }

    tmp_size = *(u32 *)((char *)tmp + g_pol_layout.hashtab_size);
    tmp_nel = *(u32 *)((char *)tmp + g_pol_layout.hashtab_nel);
    tmp_htable = *(void ***)((char *)tmp + g_pol_layout.hashtab_htable);
    if (!tmp_htable || tmp_size != lv.size) { rc = -EINVAL; goto out; }

    /* Publish into the private snapshot and retire the old clean nodes.  The
     * old table's keys/datums are now referenced by the new nodes, so only the
     * nodes and the htable array may be freed (hashtab_destroy does exactly
     * that). */
    {
        u64 old[2];
        lib_memset(old, 0, sizeof(old));
        *(void ***)((char *)old + g_pol_layout.hashtab_htable) = cv.htable;
        *(u32 *)((char *)old + g_pol_layout.hashtab_size) = cv.size;
        *(u32 *)((char *)old + g_pol_layout.hashtab_nel) = cv.nel;
        *(void ***)((char *)clean_base + g_pol_layout.hashtab_htable) = tmp_htable;
        *(u32 *)((char *)clean_base + g_pol_layout.hashtab_size) = tmp_size;
        *(u32 *)((char *)clean_base + g_pol_layout.hashtab_nel) = tmp_nel;
        kp_sh_hashtab_destroy(old);
    }
    log_boot("selinux_sepolicy: shadow %s: size %u->%u nel %u->%u, hidden=%u kept=%u\n",
             label, cv.size, tmp_size, cv.nel, tmp_nel, hidden, kept);
    return 0;

out:
    if (hidden_cnt && kp_sh_kfree) {
        for (i = 0; i < hidden_cnt; i++) kp_sh_kfree(hidden_keys[i]);
    }
    tmp_htable = *(void ***)((char *)tmp + g_pol_layout.hashtab_htable);
    if (tmp_htable) kp_sh_hashtab_destroy(tmp);
    return rc;
}

static int kp_shadow_verify_one(void *clean_base, void *live_base, const char *label)
{
    struct kp_symtab_view cv, lv;
    u32 i, matched = 0, extras = 0, mism = 0;

    kp_symtab_view(clean_base, &cv);
    kp_symtab_view(live_base, &lv);
    if (cv.size != lv.size) {
        logkfw("selinux_sepolicy: shadow verify %s: size %u vs %u\n", label, cv.size, lv.size);
        return -EINVAL;
    }
    if (!lv.htable) return cv.htable ? -EINVAL : 0;
    if (!cv.htable) return -EINVAL;

    /* Prove the live-key projection: in every bucket, the shadow's keys that
     * exist in live must appear in exactly live's order.  Clean-only extras
     * (a name live removed) are counted, not treated as a mismatch. */
    for (i = 0; i < lv.size; i++) {
        void *cn = cv.htable[i];
        void *ln = lv.htable[i];

        while (ln) {
            char *lk = *(char **)((char *)ln + g_pol_layout.node_key);
            char *ck;

            while (cn) {
                char *k = *(char **)((char *)cn + g_pol_layout.node_key);
                if (k && !kp_sh_symtab_search(live_base, k)) {
                    extras++;
                    cn = *(void **)((char *)cn + g_pol_layout.node_next);
                    continue;
                }
                break;
            }
            if (!cn) { mism++; break; }
            ck = *(char **)((char *)cn + g_pol_layout.node_key);
            if (!ck || !lk || lib_strcmp(ck, lk)) { mism++; break; }
            matched++;
            cn = *(void **)((char *)cn + g_pol_layout.node_next);
            ln = *(void **)((char *)ln + g_pol_layout.node_next);
        }
        while (cn) {
            char *k = *(char **)((char *)cn + g_pol_layout.node_key);
            if (k && !kp_sh_symtab_search(live_base, k)) extras++;
            cn = *(void **)((char *)cn + g_pol_layout.node_next);
        }
    }
    log_boot("selinux_sepolicy: shadow verify %s: size=%u matched=%u extras=%u mismatches=%u\n",
             label, cv.size, matched, extras, mism);
    return mism ? -EINVAL : 0;
}

static int kp_shadow_sym(void *clean_pdb, void *live_pdb, int sym, const char *label)
{
    void *cb = (char *)clean_pdb + g_pol_layout.policydb_symtab + (long)sym * g_pol_layout.symtab_size;
    void *lb = (char *)live_pdb + g_pol_layout.policydb_symtab + (long)sym * g_pol_layout.symtab_size;
    int rc;

    rc = kp_shadow_one_symtab(cb, lb, label);
    if (!rc) rc = kp_shadow_verify_one(cb, lb, label);
    return rc;
}

static const char *kp_val_name(void *pdb, int sym, u32 value);
static u32 kp_sym_nprim(void *pdb, int sym);
static bool g_live_values_aligned;

/* Decide once (under policy_mutex) whether every clean symbol value maps to the
 * same live name.  The fast accepted path uses this instead of per-query
 * strcmps; if a manager renumbers a symbol, the live sidtab insert is skipped. */
static bool kp_live_values_scan(void *clean_pdb, void *live_pdb)
{
    static const int syms[] = { 2 /*roles*/, 3 /*types*/, 4 /*users*/, 6 /*levels*/, 7 /*cats*/ };
    int i;
    u32 v;

    if (!clean_pdb || !live_pdb) return false;
    for (i = 0; i < (int)(sizeof(syms) / sizeof(syms[0])); i++) {
        int sym = syms[i];
        u32 cn = kp_sym_nprim(clean_pdb, sym);
        u32 ln = kp_sym_nprim(live_pdb, sym);

        if (sym == 3) { /* live may append types; the clean value range must match */
            if (ln < cn) return false;
        } else if (cn != ln) {
            return false;
        }
        for (v = 1; v <= cn; v++) {
            const char *a = kp_val_name(clean_pdb, sym, v);
            const char *b = kp_val_name(live_pdb, sym, v);
            if (!a || !b || lib_strcmp(a, b)) return false;
        }
    }
    return true;
}

/* ---- hot-path prefetch ----
 *
 * The shadow tables match live in shape, but they are cold: live's tables are
 * kept warm by the kernel's own SELinux checks.  A (valid user/role, invalid
 * type) walks into the type/role buckets; B (invalid user) exits early, so a
 * cold A costs more cycles and the A-B difference grows on a slow or
 * low-clock CPU.  Prefetch the buckets for both inputs (same cost) before
 * parsing; only A consumes the warm lines.
 *
 * Level: 0 off, 1 type only, 2 role+type, 3 user+role+type.
 */
struct kp_shadow_hot {
    bool ready;
    void *pdb;
    void **htable[8];
    u32 size[8];
};

static struct kp_shadow_hot g_hot;
static volatile int g_prefetch_level;

static u32 kp_symhash_n(const char *key, u32 len)
{
    u32 val = 0;
    u32 i;

    for (i = 0; i < len; i++)
        val = ((val << 4) | (val >> 28)) ^ (u8)key[i];
    return val;
}

static void kp_prefetch_token(int sym, const char *s, u32 len)
{
    u32 bucket;
    void *node;

    if (!g_hot.ready || !g_hot.htable[sym] || !g_hot.size[sym] || !len) return;
    bucket = kp_symhash_n(s, len) & (g_hot.size[sym] - 1);
    __builtin_prefetch(&g_hot.htable[sym][bucket], 0, 3);
    node = g_hot.htable[sym][bucket];
    if (node) __builtin_prefetch(node, 0, 3);
}

static void kp_prefetch_context(const char *s)
{
    const char *p = s;
    int field;

    if (!g_hot.ready || !s || g_prefetch_level <= 0) return;
    if (g_hot.pdb) {
        __builtin_prefetch(g_hot.pdb, 0, 3);
        __builtin_prefetch((char *)g_hot.pdb + g_pol_layout.policydb_symtab, 0, 3);
    }
    for (field = 0; field < 3 && p && *p; field++) {
        const char *start = p;
        u32 len;

        while (*p && *p != ':') p++;
        len = (u32)(p - start);
        if (field == 0) {
            if (g_prefetch_level >= 3) kp_prefetch_token(4, start, len);
        } else if (field == 1) {
            if (g_prefetch_level >= 2) kp_prefetch_token(2, start, len);
        } else {
            kp_prefetch_token(3, start, len);
        }
        if (*p == ':') p++;
    }
}

void selinux_sepolicy_set_prefetch(int level)
{
    if (level < 0) level = 0;
    if (level > 3) level = 3;
    g_prefetch_level = level;
}

static int kp_symtab_shadow(void)
{
    unsigned long state;
    kp_mutex_fn lock, unlock;
    void *policy, *live_pdb, *clean_pdb;
    int rc;

    kp_policy_layout_init();
    if (g_pol_layout.policydb_symtab < 0) return -EOPNOTSUPP;
    if (!kp_shadow_resolve()) return -EOPNOTSUPP;

    clean_pdb = kp_backup_policydb();
    if (!clean_pdb || is_bad_address(clean_pdb)) return -EINVAL;

    state = lookup_name_with_suffix("selinux_state");
    lock = (kp_mutex_fn)(uintptr_t)lookup_name_with_suffix("mutex_lock");
    unlock = (kp_mutex_fn)(uintptr_t)lookup_name_with_suffix("mutex_unlock");
    if (!state || !lock || !unlock) return -ENOENT;

    lock((void *)(state + g_pol_layout.state_policy_mutex));
    policy = *(void **)(state + g_pol_layout.state_policy);
    live_pdb = (policy && !is_bad_address(policy)) ? (char *)policy + g_pol_layout.selpolicy_policydb : NULL;
    if (!live_pdb) {
        unlock((void *)(state + g_pol_layout.state_policy_mutex));
        return -EINVAL;
    }
    /* String literals are passed straight from each call site: kpimg is moved
     * without applying relocations, so a static array of pointers would keep
     * its link-time values.  Run every symtab even if one fails: a verify
     * mismatch on roles must not leave types/users/levels/cats unshadowed. */
    {
        int one;

        rc = 0;
        one = kp_shadow_sym(clean_pdb, live_pdb, 2, "roles");
        if (one && !rc) rc = one;
        one = kp_shadow_sym(clean_pdb, live_pdb, 3, "types");
        if (one && !rc) rc = one;
        one = kp_shadow_sym(clean_pdb, live_pdb, 4, "users");
        if (one && !rc) rc = one;
        one = kp_shadow_sym(clean_pdb, live_pdb, 6, "levels");
        if (one && !rc) rc = one;
        one = kp_shadow_sym(clean_pdb, live_pdb, 7, "cats");
        if (one && !rc) rc = one;
    }
    if (!rc) {
        static const int hot_syms[] = { 2, 3, 4, 6, 7 };
        int hi;

        g_live_values_aligned = kp_live_values_scan(clean_pdb, live_pdb);
        log_boot("selinux_sepolicy: live value alignment=%d\n", g_live_values_aligned);
        g_hot.pdb = clean_pdb;
        for (hi = 0; hi < (int)(sizeof(hot_syms) / sizeof(hot_syms[0])); hi++) {
            int sym = hot_syms[hi];
            struct kp_symtab_view v;

            kp_symtab_view((char *)clean_pdb + g_pol_layout.policydb_symtab +
                           (long)sym * g_pol_layout.symtab_size, &v);
            g_hot.htable[sym] = v.htable;
            g_hot.size[sym] = v.size;
        }
        g_hot.ready = true;
    }
    unlock((void *)(state + g_pol_layout.state_policy_mutex));
    return rc;
}

int selinux_sepolicy_snapshot(void)
{
    int rc;

    if (!selinux_sepolicy_supported()) return -EOPNOTSUPP;
    if (g_backup_ready) return 0;
    rc = kp_dup_sepolicy();
    if (!rc) kp_log_policy_shapes();
    return rc;
}

int selinux_sepolicy_shadow(void)
{
    int rc;

    kp_policy_layout_init();
    if (g_pol_layout.policydb_symtab < 0) {
        log_boot("selinux_sepolicy: shadow skipped (layout unavailable)\n");
        return -EOPNOTSUPP;
    }
    /* The snapshot is rebuilt once.  Rebuilding on a later enable would need a
     * safe publish/grace period (the table is being read by query hooks); a
     * later live reload is logged as stale instead. */
    if (g_shadow_built) return 0;
    kp_log_live_policy_shapes();
    rc = kp_symtab_shadow();
    log_boot("selinux_sepolicy: shadow rc=%d\n", rc);
    kp_log_symtab_shape("shadow", kp_backup_policydb(), 3, "types", KP_PROBE_A);
    if (!rc) g_shadow_built = true;
    return rc;
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
    int rc;

    if (!policydb || !sidtab || !scontext_len) return -EINVAL;
    if (!kp_string_to_context_struct || !kp_sidtab_context_to_sid) return -ENOSYS;

    char *scontext2;
    bool via_vmalloc = false;

    if (scontext_len >= KP_CONTEXT_PAYLOAD_LIMIT) return -EINVAL;
    scontext2 = kp_payload_alloc(scontext_len + 1, gfp, &via_vmalloc);
    if (!scontext2) return -ENOMEM;
    lib_memcpy(scontext2, scontext, scontext_len);
    scontext2[scontext_len] = '\0';

    rc = kp_string_to_context_struct(policydb, sidtab, scontext2, &context, def_sid);
    if (!rc)
        rc = kp_sidtab_context_to_sid(sidtab, &context, out_sid);
    kp_payload_free(scontext2, via_vmalloc);
    return rc;
}

static struct sidtab_entry *kp_sidtab_lookup(void *sidtab, u32 sid)
{
    if (kp_sidtab_search_entry) return kp_sidtab_search_entry(sidtab, sid);
    if (kp_sidtab_search_core) return kp_sidtab_search_core(sidtab, sid, 0);
    return NULL;
}

static int kp_sid_to_context_with_policy(u32 sid, char **scontext, u32 *scontext_len)
{
    struct policydb *policydb = kp_backup_policydb();
    void *sidtab = kp_backup_sidtab();
    struct sidtab_entry *entry;
    int rc;

    if (scontext) *scontext = NULL;
    *scontext_len = 0;
    if (!policydb || !sidtab) return -EINVAL;

    entry = kp_sidtab_lookup(sidtab, sid);
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

    if (!policydb || !sidtab || !kp_context_struct_compute_av) return;
    if (!kp_sidtab_search_entry && !kp_sidtab_search_core) return;

    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    avd->seqno = KP_AVD_CLEAN_SEQNO;
    avd->flags = 0;

    se = kp_sidtab_lookup(sidtab, ssid);
    if (!se) return;
    scontext = &se->context;

    te = kp_sidtab_lookup(sidtab, tsid);
    if (!te) return;
    tcontext = &te->context;

    if (unlikely(!tclass)) {
        if (g_backup_allow_unknown) avd->allowed = 0xffffffff;
        return;
    }

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

/* ---- fast accepted path ----
 *
 * The snapshot parse already produces a struct context.  Stock also registers
 * that context in the live sidtab (the ss/sidtab_hash_stats side effect).
 * Instead of re-parsing the string, insert the same context object into the
 * live sidtab under RCU; the canonical string and the access vector are derived
 * directly from the snapshot context.  The accepted path then does no more work
 * than stock: one parse, one live sidtab insert, one canonical allocation.
 *
 * Value alignment for users/roles/types/levels/cats is decided once at shadow
 * time (g_live_values_aligned).  If the manager renumbered a symbol, the live
 * insert is skipped (the snapshot answer is unaffected) and the shadow logs it.
 */
static void (*kp_rcu_lock_fn)(void);
static void (*kp_rcu_unlock_fn)(void);
static bool kp_live_fast_init_done;
static bool kp_live_fast_ready;
static unsigned long kp_live_state_addr;
static kp_mutex_fn kp_live_lock_fn;
static kp_mutex_fn kp_live_unlock_fn;
static void (*kp_live_context_destroy)(struct context *);

static bool kp_live_fast_init(void)
{
    if (kp_live_fast_init_done) return kp_live_fast_ready;
    kp_live_fast_init_done = true;

    kp_policy_layout_init();
    if (kver < VERSION(6, 6, 0)) return false;
    if (g_pol_layout.policydb_sym_val_to_name < 0 ||
        g_pol_layout.selpolicy_sidtab < 0 ||
        !kp_sidtab_context_to_sid || !kp_string_to_context_struct)
        return false;

    kp_live_state_addr = lookup_name_with_suffix("selinux_state");
    kp_rcu_lock_fn = (void (*)(void))(uintptr_t)lookup_name_with_suffix("__rcu_read_lock");
    kp_rcu_unlock_fn = (void (*)(void))(uintptr_t)lookup_name_with_suffix("__rcu_read_unlock");
    kp_live_lock_fn = (kp_mutex_fn)(uintptr_t)lookup_name_with_suffix("mutex_lock");
    kp_live_unlock_fn = (kp_mutex_fn)(uintptr_t)lookup_name_with_suffix("mutex_unlock");
    if (!kp_live_state_addr) return false;
    if (!kp_rcu_lock_fn || !kp_rcu_unlock_fn) {
        if (!kp_live_lock_fn || !kp_live_unlock_fn) return false;
    }
    kp_live_context_destroy = (void (*)(struct context *))(uintptr_t)lookup_name_with_suffix("context_destroy");

    kp_live_fast_ready = true;
    return true;
}

static const char *kp_val_name(void *pdb, int sym, u32 value)
{
    char ***base;
    char **arr;
    const char *name;

    if (!pdb || sym < 0 || sym >= 8 || !value ||
        g_pol_layout.policydb_sym_val_to_name < 0) return NULL;
    base = (char ***)((char *)pdb + g_pol_layout.policydb_sym_val_to_name);
    if (is_bad_address(base)) return NULL;
    arr = base[sym];
    if (!arr || is_bad_address(arr)) return NULL;
    name = arr[value - 1];
    if (!name || is_bad_address((void *)(uintptr_t)name)) return NULL;
    return name;
}

static u32 kp_sym_nprim(void *pdb, int sym)
{
    if (!pdb || g_pol_layout.policydb_symtab < 0) return 0;
    return *(u32 *)((char *)pdb + g_pol_layout.policydb_symtab +
                    (long)sym * g_pol_layout.symtab_size + g_pol_layout.symtab_nprim);
}

static bool kp_fast_logged;

static int kp_live_sync(struct context *ctx)
{
    unsigned long state = kp_live_state_addr;
    void *policy, *live_sidtab;
    u32 live_sid = SECSID_NULL;
    int rc = -EOPNOTSUPP;
    int retry;

    if (!kp_live_fast_init() || !state) return -EOPNOTSUPP;
    if (!g_live_values_aligned) return -EOPNOTSUPP;

    for (retry = 0; retry < 2; retry++) {
        if (kp_rcu_lock_fn) {
            kp_rcu_lock_fn();
            policy = *(void **)(state + g_pol_layout.state_policy);
            live_sidtab = (policy && !is_bad_address(policy)) ?
                          *(void **)((char *)policy + g_pol_layout.selpolicy_sidtab) : NULL;
            if (!live_sidtab || is_bad_address(live_sidtab)) rc = -EINVAL;
            else rc = kp_sidtab_context_to_sid(live_sidtab, ctx, &live_sid);
            kp_rcu_unlock_fn();
        } else {
            kp_live_lock_fn((void *)(state + g_pol_layout.state_policy_mutex));
            policy = *(void **)(state + g_pol_layout.state_policy);
            live_sidtab = (policy && !is_bad_address(policy)) ?
                          *(void **)((char *)policy + g_pol_layout.selpolicy_sidtab) : NULL;
            if (!live_sidtab || is_bad_address(live_sidtab)) rc = -EINVAL;
            else rc = kp_sidtab_context_to_sid(live_sidtab, ctx, &live_sid);
            kp_live_unlock_fn((void *)(state + g_pol_layout.state_policy_mutex));
        }
        if (rc != -ESTALE) break;
    }
    if (!rc && !kp_fast_logged) {
        kp_fast_logged = true;
        logkfi("selinux_sepolicy: direct live sidtab insert active (no second string parse)\n");
    }
    return rc;
}

static int kp_parse_clean(char *scontext, struct context *ctx)
{
    struct policydb *pdb = kp_backup_policydb();
    void *sidtab = kp_backup_sidtab();

    if (!pdb || !sidtab || !scontext || !kp_string_to_context_struct) return -ENOSYS;
    lib_memset(ctx, 0, sizeof(*ctx));
    return kp_string_to_context_struct(pdb, sidtab, scontext, ctx, SECSID_NULL);
}

static void kp_context_release(struct context *ctx)
{
    if (!kp_live_context_destroy)
        kp_live_context_destroy = (void (*)(struct context *))(uintptr_t)lookup_name_with_suffix("context_destroy");
    if (kp_live_context_destroy) kp_live_context_destroy(ctx);
}

int selinux_sepolicy_live_aligned(void)
{
    return (g_live_values_aligned && g_string_redirect_installed) ? 1 : 0;
}

int selinux_sepolicy_context_to_canonical(char *buf, u32 size, char **canon, u32 *len)
{
    struct policydb *pdb = kp_backup_policydb();
    struct context ctx;
    int rc;

    if (!g_backup_ready || !buf || !size || !canon || !len) return -EINVAL;
    *canon = NULL;
    *len = 0;
    if (!pdb || !kp_context_struct_to_string) return -ENOSYS;

    if (g_prefetch_level > 0) kp_prefetch_context(buf);

    rc = kp_parse_clean(buf, &ctx);
    if (!rc) {
        (void)kp_live_sync(&ctx);
        rc = kp_context_struct_to_string(pdb, &ctx, canon, len);
        /* The parser destroys the context on failure, so only release after a
         * successful parse (avoids a redundant context_destroy on the A/B
         * failure path). */
        kp_context_release(&ctx);
    }
    return rc;
}

int selinux_sepolicy_access_av(char *scon, char *tcon, u16 tclass, struct av_decision *avd)
{
    struct policydb *pdb = kp_backup_policydb();
    struct context sctx, tctx;
    int rc;

    if (!g_backup_ready || !scon || !tcon || !avd) return -EINVAL;
    if (!pdb || !kp_context_struct_compute_av) return -ENOSYS;

    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    avd->seqno = KP_AVD_CLEAN_SEQNO;
    avd->flags = 0;

    if (g_prefetch_level > 0) {
        kp_prefetch_context(scon);
        kp_prefetch_context(tcon);
    }

    rc = kp_parse_clean(scon, &sctx);
    if (rc) return rc;
    rc = kp_parse_clean(tcon, &tctx);
    if (rc) {
        kp_context_release(&sctx);
        return rc;
    }
    (void)kp_live_sync(&sctx);
    (void)kp_live_sync(&tctx);
    if (unlikely(!tclass)) {
        if (g_backup_allow_unknown) avd->allowed = 0xffffffff;
    } else {
        kp_context_struct_compute_av(pdb, &sctx, &tctx, tclass, avd, NULL);
    }
    kp_context_release(&sctx);
    kp_context_release(&tctx);
    return 0;
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

static bool kp_clean_status_modern(void)
{
    return kver >= VERSION(6, 7, 0);
}

u32 selinux_sepolicy_clean_seq(void)
{
    return kp_clean_status_modern() ? KP_CLEAN_STATUS_SEQUENCE : 0;
}

u32 selinux_sepolicy_clean_policyload(void)
{
    return kp_clean_status_modern() ? KP_CLEAN_STATUS_POLICYLOAD : 0;
}

int selinux_sepolicy_clean_deny_unknown(void)
{
    if (!g_backup_ready) return 1;
    return g_backup_allow_unknown ? 0 : 1;
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
    kp_payload_resolve();
    if (!selinux_hide_is_new_version()) {
        /* Only the argument-redirect hooks are needed: the deep copy is consumed by
        * swapping the policydb argument while an app query runs. */
        addr = lookup_name_with_suffix("context_struct_compute_av");
        if (addr) {
            hook_wrap6((void *)addr, before_context_struct_compute_av, NULL, NULL);
            log_boot("selinux_sepolicy: hooked context_struct_compute_av @ %llx\n", addr);
        }
    }
    /* Also used by the >= 5.0 setprocattr fast path: the scope is entered only
     * around the stock handler, so the callback is a no-op elsewhere. */
    addr = lookup_name_with_suffix("string_to_context_struct");
    if (addr) {
        hook_err_t herr = hook_wrap5((void *)addr, before_string_to_context_struct, NULL, NULL);
        if (herr == HOOK_NO_ERR) {
            g_string_redirect_installed = true;
            log_boot("selinux_sepolicy: hooked string_to_context_struct @ %llx\n", addr);
        } else {
            logkfw("selinux_sepolicy: hook string_to_context_struct failed: %d\n", (int)herr);
        }
    }

    /* Capture policy blobs as they are loaded, so the clean copy comes from the
     * full platform policy and not from an earlier (or later, patched) epoch.
     * ABI: >= 6.4 (data, len, load_state); before that
     * (state, data, len, load_state). */
    addr = lookup_name_with_suffix("security_load_policy");
    if (addr) {
        if (selinux_hide_is_without_sepolicy_state_version())
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
