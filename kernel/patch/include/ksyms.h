#ifndef _KP_KSYMS_H
#define _KP_KSYMS_H

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
#define kfunc_match_cfi(func, name, addr)                                 \
    kf_##func = (typeof(kf_##func))kallsyms_lookup_name(#func ".cfi_jt"); \
    if (!kf_##func) kf_##func = (typeof(kf_##func))kallsyms_lookup_name(#func);

#define kfunc_call(func, ...) \
    if (kf_##func) return kf_##func(__VA_ARGS__);
#define kfunc_call_void(func, ...) \
    if (kf_##func) kf_##func(__VA_ARGS__);

// todo
#define kfunc_not_found() logke("kfunc: %s not found\n", __func__);

#endif
