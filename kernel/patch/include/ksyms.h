/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_KSYMS_H
#define _KP_KSYMS_H

#include <linux/kallsyms.h>
#include <log.h>

#define INIT_USE_KALLSYMS_LOOKUP_NAME

#define KFUNC_POISON 0xdeaddead00000000

#define kvar(var) kv_##var
#define kvar_def(var) (*kv_##var)
#define kvlen(var) kvl_##var
#define kvar_val(var) (*kvar(var))

#define kfunc(func) kf_##func
#define kfunc_def(func) (*kf_##func)

#define kvar_lookup_name(var) kv_##var = (typeof(kv_##var))kallsyms_lookup_name(#var)
#define kfunc_lookup_name(func) kf_##func = (typeof(kf_##func))kallsyms_lookup_name(#func)

#ifdef INIT_USE_KALLSYMS_LOOKUP_NAME
#define kvar_match(var, name, addr) kvar_lookup_name(var)
#define kfunc_match(func, name, addr) kfunc_lookup_name(func)
#define kfunc_match_cfi(func, name, addr)                                 \
    kf_##func = (typeof(kf_##func))kallsyms_lookup_name(#func ".cfi_jt"); \
    if (!kf_##func) kf_##func = (typeof(kf_##func))kallsyms_lookup_name(#func);
#else
int _ksym_local_strcmp(const char *s1, const char *s2);
#define kvar_match(var, name, addr) \
    if (!kv_##var && !_ksym_local_strcmp(#var, name)) kv_##var = (typeof(kv_##var))addr;
#define kfunc_match(func, name, addr) \
    if (!kf_##func && !_ksym_local_strcmp(#func, name)) kf_##func = (typeof(kf_##func))addr
#endif

#define kfunc_call(func, ...) \
    if (kf_##func) return kf_##func(__VA_ARGS__);

#define kfunc_direct_call(func, ...) return kf_##func(__VA_ARGS__);

#define kfunc_call_void(func, ...) \
    if (kf_##func) kf_##func(__VA_ARGS__);

#define kfunc_direct_call_void(func, ...) kf_##func(__VA_ARGS__);

// todo
#define kfunc_not_found() logke("kfunc: %s not found\n", __func__);

#endif
