#ifndef _KSYMS_H
#define _KSYMS_H

#include <linux/kallsyms.h>
#include <log.h>

#define kvar(var) kv_##var
#define kvar_def(var) (*kv_##var)
#define kvlen(var) kvl_##var
#define kvar_val(var) (*kvar(var))

#define kfunc(func) kf_##func
#define kfunc_def(func) (*kf_##func)

#define kvar_match(var, name, addr) kv_##var = (typeof(kv_##var))kallsyms_lookup_name(#var)
#define kfunc_match(func, name, addr) kf_##func = (typeof(kf_##func))kallsyms_lookup_name(#func)

#define kfunc_call(func, ...) \
    if (kf_##func)            \
        return kf_##func(__VA_ARGS__);
#define kfunc_call_void(func, ...) \
    if (kf_##func)                 \
        kf_##func(__VA_ARGS__);

// todo
#define kfunc_not_found() logke("kfunc: %s not found\n", __func__);

#define hook_backup(func) (*backup_##func)
#define hook_replace(func) replace_##func
#define hook_call_backup(func, ...) backup_##func(__VA_ARGS__)

#define hook_kfunc_with(func, replace, backup)                                \
    if (kfunc(func)) {                                                        \
        hook_err_t err_##func = hook(kfunc(func), replace, (void **)&backup); \
        if (err_##func != HOOK_NO_ERR) {                                      \
            logke("hook: %s, ret: %d\n", #func, err_##func);                  \
        }                                                                     \
    } else {                                                                  \
        logkw("hook: %s not found\n", #func);                                 \
    }

#define hook_kfunc(func) hook_kfunc_with(func, replace_##func, backup_##func)

#define find_and_hook_func_with(func, replace, backup)                 \
    unsigned long addr = kallsyms_lookup_name(#func);                  \
    if (addr) {                                                        \
        hook_err_t err_##func = hook(addr, replace, (void **)&backup); \
        if (err_##func != HOOK_NO_ERR) {                               \
            logke("hook: %s, ret: %d\n", #func, err_##func);           \
        }                                                              \
    } else {                                                           \
        logkw("hook: %s not found\n", #func);                          \
    }

#endif
