#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

#include <ktypes.h>
#include <stdarg.h>
#include <ksyms.h>

// void do_exit(long error_code) __noreturn;

extern int kfunc_def(sscanf)(const char *buf, const char *fmt, ...);
extern int kfunc_def(vsscanf)(const char *buf, const char *fmt, va_list args);

#define sscanf(buf, fmt, ...) kfunc(sscanf)(buf, fmt, __VA_ARGS__)

static inline int vsscanf(const char *buf, const char *fmt, va_list args)
{
    kfunc_call(vsscanf, buf, fmt, args);
    kfunc_not_found();
    return 0;
}

#endif