#ifndef _LINUX_CAPABILITY_H
#define _LINUX_CAPABILITY_H

#include <uapi/linux/capability.h>

#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#define _LINUX_CAPABILITY_U32S_3 2

#define _KERNEL_CAPABILITY_VERSION _LINUX_CAPABILITY_VERSION_3
#define _KERNEL_CAPABILITY_U32S _LINUX_CAPABILITY_U32S_3

typedef struct
{
    u64 val;
} kernel_cap_t;

#define CAP_FS_MASK                                                                                       \
    (BIT_ULL(CAP_CHOWN) | BIT_ULL(CAP_MKNOD) | BIT_ULL(CAP_DAC_OVERRIDE) | BIT_ULL(CAP_DAC_READ_SEARCH) | \
     BIT_ULL(CAP_FOWNER) | BIT_ULL(CAP_FSETID) | BIT_ULL(CAP_MAC_OVERRIDE))
#define CAP_VALID_MASK (BIT_ULL(CAP_LAST_CAP + 1) - 1)

#define CAP_EMPTY_SET ((kernel_cap_t){ 0 })
#define CAP_FULL_SET ((kernel_cap_t){ CAP_VALID_MASK })
#define CAP_FS_SET ((kernel_cap_t){ CAP_FS_MASK | BIT_ULL(CAP_LINUX_IMMUTABLE) })
#define CAP_NFSD_SET ((kernel_cap_t){ CAP_FS_MASK | BIT_ULL(CAP_SYS_RESOURCE) })

#define cap_clear(c) \
    do {             \
        (c).val = 0; \
    } while (0)

#define cap_raise(c, flag) ((c).val |= BIT_ULL(flag))
#define cap_lower(c, flag) ((c).val &= ~BIT_ULL(flag))
#define cap_raised(c, flag) (((c).val & BIT_ULL(flag)) != 0)

struct user_namespace;
struct task_struct;

extern bool has_capability(struct task_struct *t, int cap);
extern bool has_ns_capability(struct task_struct *t, struct user_namespace *ns, int cap);
extern bool has_capability_noaudit(struct task_struct *t, int cap);
extern bool has_ns_capability_noaudit(struct task_struct *t, struct user_namespace *ns, int cap);
extern bool capable(int cap);
extern bool ns_capable(struct user_namespace *ns, int cap);
extern bool ns_capable_noaudit(struct user_namespace *ns, int cap);
extern bool ns_capable_setid(struct user_namespace *ns, int cap);

extern kernel_cap_t full_cap;

#endif