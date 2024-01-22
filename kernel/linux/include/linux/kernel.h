#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

#include <ktypes.h>
#include <stdarg.h>
#include <ksyms.h>

extern int kfunc_def(sprintf)(char *buf, const char *fmt, ...);
extern int kfunc_def(vsprintf)(char *buf, const char *fmt, va_list args);
extern int kfunc_def(snprintf)(char *buf, size_t size, const char *fmt, ...);
extern int kfunc_def(vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);
extern int kfunc_def(scnprintf)(char *buf, size_t size, const char *fmt, ...);
extern int kfunc_def(vscnprintf)(char *buf, size_t size, const char *fmt, va_list args);
extern char *kfunc_def(kasprintf)(gfp_t gfp, const char *fmt, ...);
extern char *kfunc_def(kvasprintf)(gfp_t gfp, const char *fmt, va_list args);
extern int kfunc_def(sscanf)(const char *buf, const char *fmt, ...);
extern int kfunc_def(vsscanf)(const char *buf, const char *fmt, va_list args);

#define sprintf(buf, fmt, ...) kfunc(sprintf)(buf, fmt, ##__VA_ARGS__)
#define snprintf(buf, size, fmt, ...) kfunc(snprintf)(buf, size, fmt, ##__VA_ARGS__)
#define scnprintf(buf, size, fmt, ...) kfunc(scnprintf)(buf, size, fmt, ##__VA_ARGS__)
#define kasprintf(buf, fmt, ...) kfunc(kasprintf)(buf, fmt, ##__VA_ARGS__)
#define sscanf(buf, fmt, ...) kfunc(sscanf)(buf, fmt, ##__VA_ARGS__)

static inline int vsprintf(char *buf, const char *fmt, va_list args)
{
    kfunc_direct_call(vsprintf, buf, fmt, args);
}

static inline int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
    kfunc_direct_call(vsnprintf, buf, size, fmt, args);
}

static inline int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
    kfunc_direct_call(vscnprintf, buf, size, fmt, args);
}

static inline char *kvasprintf(gfp_t gfp, const char *fmt, va_list args)
{
    kfunc_direct_call(kvasprintf, gfp, fmt, args);
}

static inline int vsscanf(const char *buf, const char *fmt, va_list args)
{
    kfunc_direct_call(vsscanf, buf, fmt, args);
}

#endif