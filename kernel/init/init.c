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
#include <security/selinux/include/security.h>

void _linux_kernel_cred_sym_match(const char *name, unsigned long addr);
void _linux_kernel_pid_sym_match(const char *name, unsigned long addr);
void _linux_kernel_fork_sym_match(const char *name, unsigned long addr);
void _linux_lib_strncpy_from_user_sym_match(const char *name, unsigned long addr);
void _linxu_lib_strnlen_user_sym_match(const char *name, unsigned long addr);
void _linux_lib_string_sym_match(const char *name, unsigned long addr);
void _linux_mm_utils_sym_match(const char *name, unsigned long addr);
void _linux_lib_argv_split_sym_match(const char *name, unsigned long addr);
void _linxu_lib_kstrtox_sym_match(const char *name, unsigned long addr);
void _linux_kernel_stop_machine_sym_match(const char *name, unsigned long addr);
void _linux_init_task_sym_match(const char *name, unsigned long addr);
void _linux_lib_dump_stack_sym_match(const char *name, unsigned long addr);
void _linux_mm_vmalloc_sym_match(const char *name, unsigned long addr);
void _linux_security_security_sym_match(const char *name, unsigned long addr);
void _linux_security_selinux_avc_sym_match(const char *name, unsigned long addr);
void _linux_security_commoncap_sym_match(const char *name, unsigned long addr);
void _linux_locking_spinlock_sym_match(const char *name, unsigned long addr);
void _linux_security_selinux_sym_match(const char *name, unsigned long addr);

void linux_sybmol_len_init();

int build_struct();
int task_observer();

int _local_strcmp(const char *s1, const char *s2)
{
    while (*s1 == *s2++)
        if (*s1++ == 0)
            return (0);
    return (*(unsigned char *)s1 - *(unsigned char *)--s2);
}

int linux_symbol_init(void *data, const char *name, struct module *m, unsigned long addr)
{
    _linux_kernel_cred_sym_match(name, addr);
    _linux_kernel_pid_sym_match(name, addr);
    _linux_kernel_fork_sym_match(name, addr);
    _linux_lib_strncpy_from_user_sym_match(name, addr);
    _linxu_lib_strnlen_user_sym_match(name, addr);
    _linux_lib_string_sym_match(name, addr);
    _linux_mm_utils_sym_match(name, addr);
    _linux_lib_argv_split_sym_match(name, addr);
    _linxu_lib_kstrtox_sym_match(name, addr);
    _linux_kernel_stop_machine_sym_match(name, addr);
    _linux_security_security_sym_match(name, addr);
    _linux_init_task_sym_match(name, addr);
    _linux_lib_dump_stack_sym_match(name, addr);
    _linux_mm_vmalloc_sym_match(name, addr);
    _linux_security_selinux_avc_sym_match(name, addr);

    _linux_security_commoncap_sym_match(name, addr);
    _linux_locking_spinlock_sym_match(name, addr);

    _linux_security_selinux_sym_match(name, addr);
    return 0;
}

void before_rest_init(hook_fdata0_t *fdata, void *udata)
{
    logkd("init before rest_init\n");

#ifdef USE_KALLSYMS_LOOKUP_NAME_INSTEAD
    linux_symbol_init(0, 0, 0, 0);
    linux_sybmol_len_init();
#else
    kallsyms_on_each_symbol(linux_symbol_init, 0);
#endif
    syscall_init();
    build_struct();
    // lsm_ext_init();
    // lsm_hook_install();
    selinux_hook_install();
    task_observer();
    supercall_install();
    // su_compat(); // todo: uaccess
    logki("==== KernelPatch Everything Done ====\n");
}

int init()
{
    int err = 0;
    unsigned long rest_init_addr = kallsyms_lookup_name("rest_init");
    if (rest_init_addr)
        hook_wrap0((void *)rest_init_addr, before_rest_init, 0, 0, 0);
    return err;
}
