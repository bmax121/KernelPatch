#ifndef _KP_LSMEXT_H_
#define _KP_LSMEXT_H_

#include <ktypes.h>
#include <uapi/lsmdef.h>
#include <linux/list.h>

#define FAST_TABLE_ELEM_UNKNOWN 1
#define FAST_TABLE_ELEM_INVALID 2

#define SECID_FAST_TABLE_NUM 4096

struct lsm_pair
{
    LSM_TYPE type;
    LSM_VAL val;
};

struct task_selinux_rule
{
    u32 tsid;
    u16 tclass;
    u32 allowed;
};

struct selinux_policy
{
    struct list_head list;
    const char *scontext;
    const char *tcontext;
    const char *tclass;
    const char *perms;
};

static inline bool is_secid_fast(u32 secid)
{
    return secid >= 0 && secid < SECID_FAST_TABLE_NUM;
}

int lsm_ext_init();

#endif