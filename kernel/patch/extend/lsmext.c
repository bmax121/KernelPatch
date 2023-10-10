#include <lsmext.h>
#include <ktypes.h>
#include <error.h>
#include <minc/string.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <security/selinux/include/security.h>
#include <security/selinux/include/classmap.h>

static uint8_t *secid_fast_table = 0;
static struct selinux_policy policy_list = { 0 };

struct selinux_policy *selinux_secid_policies(u32 secid)
{
    if (is_secid_fast(secid)) {
        if (secid_fast_table[secid] == FAST_TABLE_ELEM_INVALID) {
            return 0;
        };
    }

    char *secctx = 0;
    u32 seclen = 0;
    if (security_sid_to_context(secid, &secctx, &seclen)) {
        return 0;
    }
    struct selinux_policy *find = 0;
    struct selinux_policy *policy;
    list_for_each_entry(policy, &policy_list.list, list)
    {
        if (!min_strncmp(secctx, policy->scontext, seclen)) {
            find = policy;
            break;
        }
    }

    if (!find) {
        if (is_secid_fast(secid))
            secid_fast_table[secid] = FAST_TABLE_ELEM_INVALID;
    }
    return find;
}

int add_secctx_policy(const char *secctx, const char *tcontext, const char *tclass, const char *perms)
{
    return 0;
}

int del_secctx_policy(const char *secctx, struct lsm_pair *pairs, int npair)
{
    return 0;
}

int lsm_ext_init()
{
    INIT_LIST_HEAD(&policy_list.list);

    secid_fast_table = (typeof(secid_fast_table))vmalloc(SECID_FAST_TABLE_NUM * sizeof(uint8_t));
    for (int i = 0; i < SECID_FAST_TABLE_NUM; i++)
        secid_fast_table[i] = FAST_TABLE_ELEM_UNKNOWN;

#ifdef ANDROID
        // add_secctx_policy("u:r:logd:s0", "", "dir", "search");
        // add_secctx_policy("u:r:logd:s0", "", "file", "read,open,getattr");
#endif

    return 0;
}
