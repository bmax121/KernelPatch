#ifndef __LINUX_UACCESS_H__
#define __LINUX_UACCESS_H__

#include <ktypes.h>
#include <ksyms.h>
#include <linux/seq_buf.h>
#include <linux/trace_seq.h>

#define get_fs() (current_thread_info()->addr_limit)

// todo:
// unsigned long __must_check copy_from_user(void *to, const void __user *from, unsigned long n);
// unsigned long __must_check copy_to_user(void __user *to, const void *from, unsigned long n);
// unsigned long __must_check copy_in_user(void __user *to, const void __user *from, unsigned long n);

extern long kfunc_def(strncpy_from_user)(char *dest, const char __user *src, long count);
extern __must_check long kfunc_def(strnlen_user)(const char __user *str, long n);

static inline long strncpy_from_user(char *dest, const char __user *src, long count)
{
    kfunc_call(strncpy_from_user, dest, src, count);
    kfunc_not_found();
    return 0;
}

static inline __must_check long strnlen_user(const char __user *str, long n)
{
    kfunc_call(strnlen_user, str, n);
    kfunc_not_found();
    return 0;
}

static inline unsigned long __must_check copy_to_user(void __user *to, const void *from, unsigned long n)
{
    int copy_len;
    if (!kfunc(seq_buf_to_user)) {
        // todo: malloc
        copy_len = trace_seq_copy_to_user((void *__user)to, from, n);
    } else {
        copy_len = seq_buf_copy_to_user((void *__user)to, from, n);
    }
    return copy_len;
}

#endif