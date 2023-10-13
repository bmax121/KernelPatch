#include "patch.h"

#include <log.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>
#include <accctl.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <syscall.h>
#include <lsmext.h>
#include <error.h>
#include <security/selinux/include/security.h>

int linux_symbol_init();
void linux_sybmol_len_init();
int build_struct();
int task_observer();

static inline void do_init()
{
    logki("==== KernelPatch Do Init ====\n");
    linux_symbol_init();
    linux_sybmol_len_init();
    syscall_init();
    build_struct();
    task_observer();
    selinux_hook_install();
    supercall_install();
#ifdef ANDROID
    su_compat_init();
#endif
    logki("==== KernelPatch Everything Done ====\n");
}

static void (*backup_cgroup_init)() = 0;

void replace_cgroup_init()
{
    backup_cgroup_init();
    do_init();
}

int patch()
{
    int err = 0;

    unsigned long cgroup_init_addr = kallsyms_lookup_name("cgroup_init");
    if (!cgroup_init_addr) {
        logke("Can't find symbol cgroup_init\n");
        return ERR_NO_SUCH_SYMBOL;
    }
    hook_err_t rc = hook((void *)cgroup_init_addr, (void *)replace_cgroup_init, (void **)&backup_cgroup_init);
    if (rc) {
        logke("Hook cgroup_init error: %d\n", rc);
    }
    return err;
}
