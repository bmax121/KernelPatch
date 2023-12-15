#ifndef _KP_KPMODULE_H_
#define _KP_KPMODULE_H_

#define KPM_INFO(name, info, limit)                                   \
    _Static_assert(sizeof(info) <= limit, "Info string is too long"); \
    static const char __kpm_info_##name[] __attribute__((__used__))   \
    __attribute__((section(".kpm.info"), unused, aligned(1))) = #name "=" info

#define KPM_NAME_LEN 32
#define KPM_VERSION_LEN 12
#define KPM_LICENSE_LEN 32
#define KPM_AUTHOR_LEN 32
#define KPM_DESCRIPTION_LEN 512

#define KPM_NAME(x) KPM_INFO(name, x, KPM_NAME_LEN)
#define KPM_VERSION(x) KPM_INFO(version, x, KPM_VERSION_LEN)
#define KPM_LICENSE(x) KPM_INFO(license, x, KPM_LICENSE_LEN)
#define KPM_AUTHOR(x) KPM_INFO(author, x, KPM_AUTHOR_LEN)
#define KPM_DESCRIPTION(x) KPM_INFO(description, x, KPM_DESCRIPTION_LEN)

typedef int (*initcall_t)(const char *args);
typedef void (*exitcall_t)();

#define KPM_INIT(fn) \
    static initcall_t __kpm_initcall_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.init"))) = fn

#define KPM_EXIT(fn) \
    static exitcall_t __kpm_exitcall_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.exit"))) = fn

#endif