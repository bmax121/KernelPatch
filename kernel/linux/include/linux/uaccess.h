#ifndef __LINUX_UACCESS_H__
#define __LINUX_UACCESS_H__

#include <ktypes.h>
#include <ksyms.h>

#define get_fs() (current_thread_info()->addr_limit)

// todo:
// probe_user_write
// unsigned long __must_check copy_from_user(void *to, const void __user *from, unsigned long n);
// unsigned long __must_check copy_to_user(void __user *to, const void *from, unsigned long n);
// unsigned long __must_check copy_in_user(void __user *to, const void __user *from, unsigned long n);

//  >= 5.8, On success, returns the length of the string INCLUDING the trailing NUL.
extern long kfunc_def(strncpy_from_user_nofault)(char *dst, const void __user *unsafe_addr, long count);

/**
 * strncpy_from_unsafe_user: - Copy a NUL terminated string from unsafe user
 *				address.
 * @dst:   Destination address, in kernel space.  This buffer must be at
 *         least @count bytes long.
 * @unsafe_addr: Unsafe user address.
 * @count: Maximum number of bytes to copy, including the trailing NUL.
 *
 * Copies a NUL-terminated string from unsafe user address to kernel buffer.
 *
 * On success, returns the length of the string INCLUDING the trailing NUL.
 *
 * If access fails, returns -EFAULT (some data may have been copied
 * and the trailing NUL added).
 *
 * If @count is smaller than the length of the string, copies @count-1 bytes,
 * sets the last byte of @dst buffer to NUL and returns @count.
 */
extern long kfunc_def(strncpy_from_unsafe_user)(char *dst, const void __user *unsafe_addr, long count);

/**
 * strncpy_from_user: - Copy a NUL terminated string from userspace.
 * @dst:   Destination address, in kernel space.  This buffer must be at
 *         least @count bytes long.
 * @src:   Source address, in user space.
 * @count: Maximum number of bytes to copy, including the trailing NUL.
 *
 * Copies a NUL-terminated string from userspace to kernel space.
 *
 * On success, returns the length of the string (not including the trailing
 * NUL).
 *
 * If access to userspace fails, returns -EFAULT (some data may have been
 * copied).
 *
 * If @count is smaller than the length of the string, copies @count bytes
 * and returns @count.
 */
extern long kfunc_def(strncpy_from_user)(char *dest, const char __user *src, long count);

// Unlike strnlen_user, this can be used from IRQ handler etc. because it disables pagefaults.
extern long kfunc_def(strnlen_user_nofault)(const void __user *unsafe_addr, long count);
extern long kfunc_def(strnlen_unsafe_user)(const void __user *unsafe_addr, long count);
extern long kfunc_def(strnlen_user)(const char __user *str, long n);

long compat_strncpy_from_user(char *dest, const char __user *src, long count);

#endif