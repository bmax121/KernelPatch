#include "init.h"

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
    // _linux_lib_argv_split_sym_match();
    // _linxu_lib_kstrtox_sym_match();
    // _linux_security_security_sym_match();

    return 0;
}

void do_init(hook_fdata0_t *fdata, void *udata)
{
    linux_symbol_init();
    linux_sybmol_len_init();

    syscall_init();
    build_struct();
    selinux_hook_install();
    task_observer();
    supercall_install();
    // su_compat(); // todo: uaccess

    logki("==== KernelPatch Everything Done ====\n");
}

int init()
{
    int err = 0;

    // rest_init not work on 4.4
    unsigned long cgroup_init_addr = kallsyms_lookup_name("cgroup_init");
    if (!cgroup_init_addr) {
        logke("Can't find symbol cgroup_init\n");
        return ERR_NO_SUCH_SYMBOL;
    }
    hook_wrap0((void *)cgroup_init_addr, 0, do_init, 0, 0);
    return err;
}
