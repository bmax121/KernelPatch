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

void _linux_kernel_cred_sym_match();
void _linux_kernel_pid_sym_match();
void _linux_kernel_fork_sym_match();
void _linux_lib_strncpy_from_user_sym_match();
void _linxu_lib_strnlen_user_sym_match();
void _linux_lib_string_sym_match();
void _linux_mm_utils_sym_match();
void _linux_lib_argv_split_sym_match();
void _linxu_lib_kstrtox_sym_match();
void _linux_kernel_stop_machine_sym_match();
void _linux_init_task_sym_match();
void _linux_lib_dump_stack_sym_match();
void _linux_mm_vmalloc_sym_match();
void _linux_security_security_sym_match();
void _linux_security_selinux_avc_sym_match();
void _linux_security_commoncap_sym_match();
void _linux_locking_spinlock_sym_match();
void _linux_security_selinux_sym_match();
void _linux_lib_seq_buf_sym_match();
void _linux_fs_sym_match();

void linux_sybmol_len_init();

int build_struct();
int task_observer();

int linux_symbol_init()
{
    _linux_kernel_cred_sym_match();
    _linux_kernel_pid_sym_match();
    _linux_kernel_fork_sym_match();
    _linux_lib_strncpy_from_user_sym_match();
    _linxu_lib_strnlen_user_sym_match();
    _linux_mm_utils_sym_match();
    _linux_kernel_stop_machine_sym_match();
    _linux_init_task_sym_match();
    _linux_lib_dump_stack_sym_match();
    _linux_mm_vmalloc_sym_match();
    _linux_security_selinux_avc_sym_match();
    _linux_security_commoncap_sym_match();
    _linux_locking_spinlock_sym_match();
    _linux_security_selinux_sym_match();
    _linux_lib_string_sym_match();
    _linux_lib_seq_buf_sym_match();
    _linux_fs_sym_match();

    // _linux_lib_argv_split_sym_match();
    // _linxu_lib_kstrtox_sym_match();
    // _linux_security_security_sym_match();

    return 0;
}

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
