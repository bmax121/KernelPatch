#ifndef _KP_KPMODULE_H_
#define _KP_KPMODULE_H_

#define MAX_KPM_NUM 32

#define KPM_INFO(name, info)                                        \
    static const char __kpm_info_##name[] __attribute__((__used__)) \
    __attribute__((section(".kpm.info"), unused, aligned(1))) = #name "=" info

#define KPM_NAME(x) KPM_INFO(name, x)
#define KPM_VERSION(x) KPM_INFO(version, x)
#define KPM_LICENSE(x) KPM_INFO(license, x)
#define KPM_AUTHOR(x) KPM_INFO(author, x)
#define KPM_DESCRIPTION(x) KPM_INFO(description, x)

typedef int (*initcall_t)(const char *args);
typedef void (*exitcall_t)();

#define KPM_INIT(fn) \
    static initcall_t __kpm_initcall_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.init"))) = fn

#define KPM_EXIT(fn) \
    static exitcall_t __kpm_exitcall_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.exit"))) = fn

#endif