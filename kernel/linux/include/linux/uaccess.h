#ifndef __LINUX_UACCESS_H__
#define __LINUX_UACCESS_H__

#include <ktypes.h>
#include <ksyms.h>

#define get_fs() (current_thread_info()->addr_limit)

// todo:
// unsigned long __must_check copy_from_user(void *to, const void __user *from, unsigned long n);
// unsigned long __must_check copy_to_user(void __user *to, const void *from, unsigned long n);
// unsigned long __must_check copy_in_user(void __user *to, const void __user *from, unsigned long n);

//  >= 5.8, On success, returns the length of the string INCLUDING the trailing NUL.
extern long kfunc_def(strncpy_from_user_nofault)(char *dst, const void __user *unsafe_addr, long count);
// >= 5.3, On success, returns the length of the string INCLUDING the trailing NUL.
extern long kfunc_def(strncpy_from_unsafe_user)(char *dst, const void __user *unsafe_addr, long count);
// all, On success, returns the length of the string (not including the trailing* NUL).
extern long kfunc_def(strncpy_from_user)(char *dest, const char __user *src, long count);

// Unlike strnlen_user, this can be used from IRQ handler etc. because it disables pagefaults.
extern long kfunc_def(strnlen_user_nofault)(const void __user *unsafe_addr, long count);
extern long kfunc_def(strnlen_unsafe_user)(const void __user *unsafe_addr, long count);
extern long kfunc_def(strnlen_user)(const char __user *str, long n);

// On success, returns the length of the string INCLUDING the trailing NUL.
static inline long strncpy_from_user_nofault(char *dest, const char __user *src, long count)
{
    kfunc_call(strncpy_from_user_nofault, dest, src, count);
    kfunc_call(strncpy_from_unsafe_user, dest, src, count);
    if (kfunc(strncpy_from_user)) {
        // todo: maybe fault
        long rc = kfunc(strncpy_from_user)(dest, src, count);
        if (rc > 0) return rc + 1;
        return rc;
    }
    kfunc_not_found();
    return 0;
}

static inline long strnlen_user_nofault(const char __user *str, long n)
{
    kfunc_call(strnlen_user_nofault, str, n);
    kfunc_call(strnlen_unsafe_user, str, n);
    kfunc_not_found();
    return 0;
}

static inline long strnlen_user(const char __user *str, long n)
{
    kfunc_call(strnlen_user, str, n);
    kfunc_not_found();
    return 0;
}

#endif