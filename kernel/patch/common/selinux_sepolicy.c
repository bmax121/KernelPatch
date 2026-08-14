/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 *
 * 
 *
 * 
 * (clean) policydb to a blob, then deserializes it into a standalone
 * policydb + sidtab, and answers context/access queries against that backup.
 * We mirror that, split by the security_* API era:
 *
 *  - 4.19 .. 6.3 (compat): the helpers still take a struct selinux_state *, so
 *    we build the backup with security_read_policy() + policydb_read() +
 *    policydb_load_isids(), point a fake state at it, and call the helpers with
 *    that fake state.  policydb/sidtab are laid out in generous local buffers
 *    (kernel code writes them at its own compiled offsets, so no kernel struct
 *    definitions are required beyond the policydb layouts below).
 *
 *  - >= 6.4: the helpers no longer take a state.  Same self-contained deep copy
 *    (security_read_policy() + policydb_read() + policydb_load_isids()), then
 *    the thin security_*_with_policy wrappers on top of the resolvable ss/
 *    internals (string_to_context_struct / sidtab_* / context_struct_compute_av
 *    are all present in kallsyms on GKI).  `struct selinux_policy` layout used
 *    here: { struct sidtab *sidtab; @0  struct policydb policydb; @8 ... }.
 *
 *    NOTE: we deliberately do NOT use security_load_policy() for the backup --
 *    it starts an async sidtab-conversion workqueue that cannot be safely
 *    cancelled and wedges the workqueue pool, freezing the system.
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
#include <uapi/asm-generic/errno.h>
#include <security/selinux/include/security.h>
#include <security/selinux/include/avc.h>

/* ---- constants ---- */

#define KP_SEPOLICY_MIN_VERSION VERSION(4, 19, 0)
#define KP_SEPOLICY_WITH_POLICY_MIN_VERSION VERSION(6, 4, 0) /* helpers drop the state arg here */

#define KP_POLICY_POLICYDB_OFFSET (sizeof(void *)) /* struct selinux_policy { sidtab*, policydb, ... } */
#define KP_BACKUP_POLICY_SIZE 0x8000 /* holds the standalone policydb (6.x policydb is large) */
#define KP_BACKUP_SIDTAB_SIZE 0x4000
#define KP_FAKE_STATE_SIZE 512
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
static void *g_backup_policy; /* struct selinux_policy * (real on >= 6.4, wrapper on < 6.4) */
static unsigned char g_backup_policy_buf[KP_BACKUP_POLICY_SIZE] __attribute__((aligned(16)));
static unsigned char g_backup_sidtab_buf[KP_BACKUP_SIDTAB_SIZE] __attribute__((aligned(16)));
static unsigned char g_fake_state_buf[KP_FAKE_STATE_SIZE] __attribute__((aligned(16)));
static int g_state_policy_offset = -1;
static void *g_live_policy;    /* last committed struct selinux_policy * */
static int g_policydb_offset = -1; /* offsetof(struct selinux_policy, policydb), learned at runtime */

static bool selinux_sepolicy_supported(void)
{
    return kver >= KP_SEPOLICY_MIN_VERSION;
}

static struct policydb *kp_backup_policydb(void);
static void *kp_backup_sidtab(void);
static int kp_policydb_off(void);
int selinux_sepolicy_snapshot(void);
static int kp_context_to_sid_with_policy(const char *scontext, u32 scontext_len, u32 *out_sid, u32 def_sid,
                                         gfp_t gfp);
static int kp_sid_to_context_with_policy(u32 sid, char **scontext, u32 *scontext_len);
static void kp_compute_av_user_with_policy(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);

static bool selinux_sepolicy_use_fake_state(void)
{
    return kver < KP_SEPOLICY_WITH_POLICY_MIN_VERSION;
}

/* ---- < 6.4: fake_state construction + offset learning ---- */

/* After a policy commit, state->policy == load_state->policy: capture the live
 * policy pointer and (for the fake_state path) the state->policy field offset. */
static void kp_capture_committed_policy(void *load_state)
{
    void *policy;

    if (is_bad_address(load_state)) return;
    policy = *(void **)load_state; /* load_state->policy (first member) */
    if (is_bad_address(policy) || !policy) return;

    if (!g_live_policy) g_live_policy = policy;

    if (g_state_policy_offset < 0 && kvar(selinux_state)) {
        for (int i = 0; i < KP_FAKE_STATE_SIZE; i += sizeof(void *)) {
            if (*(void **)((char *)kvar(selinux_state) + i) == policy) {
                g_state_policy_offset = i;
                log_boot("selinux_sepolicy: state->policy offset = %d (%llx)\n", i, (unsigned long)policy);
                break;
            }
        }
    }
}

/* selinux_complete_init() runs once the initial (stock) policy is loaded and
 * selinux is fully initialized -- before a root solution reloads the policy with
 * its own rules.  Snapshot there for a pre-root backup.  (security_read_policy
 * is unavailable at the first commit because selinux is not yet initialized.) */
static void after_selinux_complete_init(hook_fargs0_t *a, void *u)
{
    int rc = selinux_sepolicy_snapshot();
    log_boot("selinux_sepolicy: complete_init snapshot rc=%d\n", rc);
}

/* < 6.4: void selinux_policy_commit(struct selinux_state *state, struct selinux_load_state *load_state) */
static void after_selinux_policy_commit_2arg(hook_fargs2_t *a, void *u)
{
    kp_capture_committed_policy((void *)a->arg1);
}

/* >= 6.4: void selinux_policy_commit(struct selinux_load_state *load_state) */
static void after_selinux_policy_commit_1arg(hook_fargs1_t *a, void *u)
{
    kp_capture_committed_policy((void *)a->arg0);
}

/* context_struct_compute_av(policydb, scontext, tcontext, tclass, avd, xperms):
 * arg0 is the policydb of the policy currently in use; with the committed
 * policy pointer this yields offsetof(struct selinux_policy, policydb). */
static void before_context_struct_compute_av(hook_fargs6_t *a, void *u)
{
    void *policydb, *p;
    long diff;

    if (g_policydb_offset >= 0 || !g_live_policy) return;
    policydb = (void *)a->arg0;
    if (is_bad_address(policydb)) return;
    p = g_live_policy;
    if (policydb <= p) return;
    diff = (long)((char *)policydb - (char *)p);
    if (diff > 0x100000) return; /* not an inline member of the committed policy */
    g_policydb_offset = (int)diff;
    log_boot("selinux_sepolicy: policydb offset = %d\n", g_policydb_offset);
}

/* Deep copy the clean policy via policydb_read + policydb_load_isids
 *  and build a fake state pointing at it. */
static int kp_snapshot_fake_state(void)
{
    struct policy_file fp;
    struct policydb *pdb;
    void *data = NULL;
    size_t len = 0;
    int rc;

    if (g_state_policy_offset < 0) {
        log_boot("selinux_sepolicy: state->policy offset unknown, backup unavailable\n");
        return -EAGAIN;
    }
    if (!kvar(selinux_state)) {
        log_boot("selinux_sepolicy: selinux_state not resolved\n");
        return -ENOENT;
    }
    if (!kfunc(security_read_policy) || !kp_policydb_read || !kp_policydb_load_isids) {
        log_boot("selinux_sepolicy: required symbols missing\n");
        return -ENOENT;
    }

    rc = security_read_policy(&data, &len);
    if (rc || !data || !len) {
        log_boot("selinux_sepolicy: security_read_policy failed rc=%d\n", rc);
        if (data && kfunc(kvfree)) kfunc(kvfree)(data);
        return rc ? rc : -EINVAL;
    }

    /* The kernel's security_* helpers read policy->policydb at the kernel's own
     * offset, so place the parsed policydb in the wrapper at the learned offset
     * (fall back to the standard sidtab*,policydb layout for old kernels). */
    pdb = (struct policydb *)(g_backup_policy_buf +
                              (g_policydb_offset >= 0 ? g_policydb_offset : KP_POLICY_POLICYDB_OFFSET));
    fp.data = data;
    fp.len = len;
    rc = kp_policydb_read(pdb, &fp);
    if (kfunc(kvfree)) kfunc(kvfree)(data);
    if (rc) {
        log_boot("selinux_sepolicy: policydb_read failed rc=%d\n", rc);
        return rc;
    }

    rc = kp_policydb_load_isids(pdb, (void *)g_backup_sidtab_buf);
    if (rc) {
        log_boot("selinux_sepolicy: policydb_load_isids failed rc=%d\n", rc);
        if (kp_policydb_destroy) kp_policydb_destroy(pdb);
        return rc;
    }

    *(void **)g_backup_policy_buf = g_backup_sidtab_buf; /* policy->sidtab @0 */
    g_backup_policy = g_backup_policy_buf;

    lib_memcpy(g_fake_state_buf, kvar(selinux_state), sizeof(g_fake_state_buf));
    *(void **)(g_fake_state_buf + g_state_policy_offset) = g_backup_policy;

    g_backup_ready = true;
    log_boot("selinux_sepolicy: backup ready via fake_state (policyvers %u, len %zu)\n", pdb->policyvers, pdb->len);
    return 0;
}

/* ---- >= 6.4: policydb_read + policydb_load_isids backup + *_with_policy wrappers ---- */

/* Same deep-copy as ksu_dup_sepolicy: serialize the live policy to a
 * blob, then rebuild a standalone policydb + fresh sidtab in our own buffers.
 * Unlike security_load_policy() this starts no sidtab-conversion workqueue and
 * never touches the live policy, so it cannot wedge a workqueue pool. */
static int kp_snapshot_with_policy(void)
{
    struct policy_file fp;
    struct policydb *pdb;
    void *data = NULL;
    size_t len = 0;
    int rc;

    if (!kfunc(security_read_policy) || !kp_policydb_read || !kp_policydb_load_isids) {
        log_boot("selinux_sepolicy: security_read_policy/policydb_read not resolved\n");
        return -ENOENT;
    }

    rc = security_read_policy(&data, &len);
    if (rc || !data || !len) {
        log_boot("selinux_sepolicy: security_read_policy failed rc=%d\n", rc);
        if (data && kfunc(kvfree)) kfunc(kvfree)(data);
        return rc ? rc : -EINVAL;
    }

    pdb = (struct policydb *)(g_backup_policy_buf + kp_policydb_off());
    fp.data = data;
    fp.len = len;
    rc = kp_policydb_read(pdb, &fp);
    if (kfunc(kvfree)) kfunc(kvfree)(data);
    if (rc) {
        log_boot("selinux_sepolicy: policydb_read failed rc=%d\n", rc);
        return rc;
    }

    rc = kp_policydb_load_isids(pdb, (void *)g_backup_sidtab_buf);
    if (rc) {
        log_boot("selinux_sepolicy: policydb_load_isids failed rc=%d\n", rc);
        if (kp_policydb_destroy) kp_policydb_destroy(pdb);
        return rc;
    }

    *(void **)g_backup_policy_buf = g_backup_sidtab_buf; /* policy->sidtab @0 */
    g_backup_policy = g_backup_policy_buf;
    g_backup_ready = true;
    log_boot("selinux_sepolicy: backup ready via policydb_read (%llx, pdb off %d)\n",
             (unsigned long)g_backup_policy, g_policydb_offset);
    return 0;
}

int selinux_sepolicy_snapshot(void)
{
    if (!selinux_sepolicy_supported()) return -EOPNOTSUPP;
    if (g_backup_ready) return 0;
    if (selinux_sepolicy_use_fake_state()) return kp_snapshot_fake_state();
    return kp_snapshot_with_policy();
}

bool selinux_sepolicy_backup_ready(void)
{
    return g_backup_ready;
}

/* ---- 6.4+ query helpers against the backup policy ---- */

static int kp_policydb_off(void)
{
    /* offsetof(struct selinux_policy, policydb); learned from the live policy,
     * falls back to the standard { sidtab*, policydb } layout. */
    return (g_policydb_offset >= 0) ? g_policydb_offset : KP_POLICY_POLICYDB_OFFSET;
}

static struct policydb *kp_backup_policydb(void)
{
    if (is_bad_address(g_backup_policy)) return NULL;
    return (struct policydb *)((char *)g_backup_policy + kp_policydb_off());
}

static void *kp_backup_sidtab(void)
{
    if (is_bad_address(g_backup_policy)) return NULL;
    return *(void **)g_backup_policy;
}

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

/* ---- public query dispatch ---- */

int selinux_sepolicy_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp)
{
    if (!g_backup_ready) return -ENOSYS;
    if (selinux_sepolicy_use_fake_state()) {
        return ((selinux_compat_kf_security_context_to_sid_t)kfunc(security_context_to_sid))(
            (struct selinux_state *)g_fake_state_buf, scontext, scontext_len, out_sid, gfp);
    }
    return kp_context_to_sid_with_policy(scontext, scontext_len, out_sid, SECSID_NULL, gfp);
}

int selinux_sepolicy_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
{
    if (!g_backup_ready) return -ENOSYS;
    if (selinux_sepolicy_use_fake_state()) {
        return ((selinux_compat_kf_security_sid_to_context_t)kfunc(security_sid_to_context))(
            (struct selinux_state *)g_fake_state_buf, sid, scontext, scontext_len);
    }
    return kp_sid_to_context_with_policy(sid, scontext, scontext_len);
}

int selinux_sepolicy_context_str_to_sid(const char *scontext, u32 *out_sid, gfp_t gfp)
{
    if (!g_backup_ready) return -ENOSYS;
    if (selinux_sepolicy_use_fake_state()) {
        return ((selinux_compat_kf_security_context_str_to_sid_t)kfunc(security_context_str_to_sid))(
            (struct selinux_state *)g_fake_state_buf, scontext, out_sid, gfp);
    }
    return kp_context_to_sid_with_policy(scontext, lib_strlen(scontext), out_sid, SECSID_NULL, gfp);
}

void selinux_sepolicy_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
    if (!g_backup_ready) return;
    if (selinux_sepolicy_use_fake_state()) {
        ((selinux_compat_kf_security_compute_av_user_t)kfunc(security_compute_av_user))(
            (struct selinux_state *)g_fake_state_buf, ssid, tsid, tclass, avd);
        avd->seqno = KP_AVD_CLEAN_SEQNO; /* clean latest_granting */
        return;
    }
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

    kp_policydb_read = (policydb_read_fn)kallsyms_lookup_name("policydb_read");
    kp_policydb_load_isids = (policydb_load_isids_fn)kallsyms_lookup_name("policydb_load_isids");
    kp_policydb_destroy = (policydb_destroy_fn)kallsyms_lookup_name("policydb_destroy");

    /* 6.4+ ss/ internals for the *_with_policy wrappers. */
    kp_string_to_context_struct = (string_to_context_struct_fn)kallsyms_lookup_name("string_to_context_struct");
    kp_sidtab_context_to_sid = (sidtab_context_to_sid_fn)kallsyms_lookup_name("sidtab_context_to_sid");
    kp_sidtab_search_entry = (sidtab_search_entry_fn)kallsyms_lookup_name("sidtab_search_entry");
    kp_sidtab_sid2str_get = (sidtab_sid2str_get_fn)kallsyms_lookup_name("sidtab_sid2str_get");
    kp_sidtab_sid2str_put = (sidtab_sid2str_put_fn)kallsyms_lookup_name("sidtab_sid2str_put");
    kp_context_struct_to_string = (context_struct_to_string_fn)kallsyms_lookup_name("context_struct_to_string");
    kp_sidtab_search_core = (sidtab_search_core_fn)kallsyms_lookup_name("sidtab_search_core");
    kp_context_struct_compute_av = (context_struct_compute_av_fn)kallsyms_lookup_name("context_struct_compute_av");

    /* Learn offsetof(struct selinux_policy, policydb) and (fake_state path) the
     * state->policy field offset from the live policy. */
    addr = kallsyms_lookup_name("selinux_policy_commit");
    if (!addr) addr = lookup_name_with_suffix("selinux_policy_commit");
    if (addr) {
        if (selinux_sepolicy_use_fake_state())
            hook_wrap2((void *)addr, after_selinux_policy_commit_2arg, NULL, NULL);
        else
            hook_wrap1((void *)addr, after_selinux_policy_commit_1arg, NULL, NULL);
        log_boot("selinux_sepolicy: hooked selinux_policy_commit @ %llx\n", addr);
    }
    addr = kallsyms_lookup_name("context_struct_compute_av");
    if (!addr) addr = lookup_name_with_suffix("context_struct_compute_av");
    if (addr) {
        hook_wrap6((void *)addr, before_context_struct_compute_av, NULL, NULL);
        log_boot("selinux_sepolicy: hooked context_struct_compute_av @ %llx\n", addr);
    }
    addr = kallsyms_lookup_name("selinux_complete_init");
    if (!addr) addr = lookup_name_with_suffix("selinux_complete_init");
    if (addr) {
        hook_wrap0((void *)addr, after_selinux_complete_init, NULL, NULL);
        log_boot("selinux_sepolicy: hooked selinux_complete_init @ %llx\n", addr);
    }

    log_boot("selinux_sepolicy: read=%llx str2ctx=%llx sidtab2sid=%llx search=%llx\n",
             (unsigned long)kfunc(security_read_policy), (unsigned long)kp_string_to_context_struct,
             (unsigned long)kp_sidtab_context_to_sid, (unsigned long)kp_sidtab_search_entry);
    log_boot("selinux_sepolicy: sid2str=%llx ctx2str=%llx search_core=%llx compute_av=%llx\n",
             (unsigned long)kp_sidtab_sid2str_get, (unsigned long)kp_context_struct_to_string,
             (unsigned long)kp_sidtab_search_core, (unsigned long)kp_context_struct_compute_av);
    return 0;
}
