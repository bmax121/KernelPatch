#ifndef _KSYMS_H
#define _KSYMS_H

#include <linux/kallsyms.h>
#include <log.h>

int _local_strcmp(const char *s1, const char *s2);

// todo: Crash on Pixel3xl android 12 when call kallsyms_on_each_symbol,
#define USE_KALLSYMS_LOOKUP_NAME_INSTEAD

#define kvar(var) kv_##var
#define kvlen(var) kvl_##var
#define kfunc(func) kf_##func
#define kfunc_def(func) (*kf_##func)

#ifdef USE_KALLSYMS_LOOKUP_NAME_INSTEAD
#define kvar_match(var, name, addr) kv_##var = (typeof(kv_##var))kallsyms_lookup_name(#var)
#define kfunc_match(func, name, addr) kf_##func = (typeof(kf_##func))kallsyms_lookup_name(#func)
#else
#define kvar_match(var, name, addr) \
    if (!kv_##var && !_local_strcmp(#var, name)) kv_##var = (typeof(kv_##var))addr;
#define kfunc_match(func, name, addr) \
    if (!kf_##func && !_local_strcmp(#func, name)) kf_##func = (typeof(kf_##func))addr
#define kvar_match_len(var, name, addr)            \
    if (!kv_##var && !_local_strcmp(#var, name)) { \
        kv_##var = (typeof(kv_##var))addr;         \
        kvl_##var = 0;                             \
    }                                              \
    if (kv_##var && !kvl_##var) { kvl_##var = addr - (uint64_t)kv_##var; }
#endif

#define kfunc_call(func, ...) \
    if (kf_##func) return kf_##func(__VA_ARGS__);
#define kfunc_call_void(func, ...) \
    if (kf_##func) kf_##func(__VA_ARGS__);

// todo
#define kfunc_not_found() logke("kfunc: %s not found\n", __func__);

#define hook_backup(func) (*backup_##func)
#define hook_replace(func) replace_##func
#define hook_call_backup(func, ...) backup_##func(__VA_ARGS__)

#define hook_kfunc(func)                                                                   \
    if (kfunc(func)) {                                                                     \
        hook_err_t err##func = hook(kfunc(func), replace_##func, (void **)&backup_##func); \
        if (err##func != HOOK_NO_ERR) {                                                    \
            logke("hook: %s, ret: %d\n", #func, err##func);                                \
        } else {                                                                           \
            logkv("hook: %s, ret: %d\n", #func, err##func);                                \
        }                                                                                  \
    } else {                                                                               \
        logkv("hook: %s not found\n", #func);                                              \
    }

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
void _linux_mm_vmalloc_sym_match(const char *name, unsigned long addr);
void _linux_security_security_sym_match(const char *name, unsigned long addr);
void _linux_security_selinux_avc_sym_match(const char *name, unsigned long addr);
void _linux_security_commoncap_sym_match(const char *name, unsigned long addr);
void _linux_locking_spinlock_sym_match(const char *name, unsigned long addr);

#endif
