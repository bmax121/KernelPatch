/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ksyms.h>
#include <ktypes.h>
#include <symbol.h>
#include <common.h>
#include <stdarg.h>

// lib/dump_stack.c
void kfunc_def(dump_stack_lvl)(const char *log_lvl) = 0;
void kfunc_def(dump_stack)(void) = 0;

static void _linux_lib_misc(const char *name, unsigned long addr)
{
    kfunc_match(dump_stack_lvl, name, addr);
    kfunc_match(dump_stack, name, addr);
}

#include <linux/uaccess.h>

long kfunc_def(strncpy_from_user_nofault)(char *dst, const void __user *unsafe_addr, long count) = 0;
long kfunc_def(strncpy_from_unsafe_user)(char *dst, const void __user *unsafe_addr, long count) = 0;
long kfunc_def(strncpy_from_user)(char *dest, const char __user *src, long count) = 0;

long kfunc_def(strnlen_user_nofault)(const void __user *unsafe_addr, long count) = 0;
long kfunc_def(strnlen_unsafe_user)(const void __user *unsafe_addr, long count) = 0;
long kfunc_def(strnlen_user)(const char __user *str, long n);

static void _linux_lib_strncpy_from_user_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(strncpy_from_user_nofault, name, addr);
    kfunc_match(strncpy_from_unsafe_user, name, addr);
    kfunc_match(strncpy_from_user, name, addr);

    // kfunc_match(strnlen_user_nofault, name, addr);
    // kfunc_match(strnlen_unsafe_user, name, addr);
    // kfunc_match(strnlen_user, name, addr);
}

// lib/string.c
#include <linux/string.h>

int kfunc_def(strncasecmp)(const char *s1, const char *s2, size_t len) = 0;
KP_EXPORT_SYMBOL(kfunc(strncasecmp));
int kfunc_def(strcasecmp)(const char *s1, const char *s2) = 0;
KP_EXPORT_SYMBOL(kfunc(strcasecmp));
char *kfunc_def(strcpy)(char *dest, const char *src) = 0;
KP_EXPORT_SYMBOL(kfunc(strcpy));
char *kfunc_def(strncpy)(char *dest, const char *src, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(strncpy));
size_t kfunc_def(strlcpy)(char *dest, const char *src, size_t size) = 0;
KP_EXPORT_SYMBOL(kfunc(strlcpy));
ssize_t kfunc_def(strscpy)(char *dest, const char *src, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(strscpy));
ssize_t kfunc_def(strscpy_pad)(char *dest, const char *src, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(strscpy_pad));
char *kfunc_def(stpcpy)(char *__restrict__ dest, const char *__restrict__ src) = 0;
KP_EXPORT_SYMBOL(kfunc(stpcpy));
char *kfunc_def(strcat)(char *dest, const char *src) = 0;
KP_EXPORT_SYMBOL(kfunc(strcat));
char *kfunc_def(strncat)(char *dest, const char *src, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(strncat));
size_t kfunc_def(strlcat)(char *dest, const char *src, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(strlcat));
int kfunc_def(strcmp)(const char *cs, const char *ct) = 0;
KP_EXPORT_SYMBOL(kfunc(strcmp));
int kfunc_def(strncmp)(const char *cs, const char *ct, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(strncmp));
char *kfunc_def(strchr)(const char *s, int c) = 0;
KP_EXPORT_SYMBOL(kfunc(strchr));
char *kfunc_def(strchrnul)(const char *s, int c) = 0;
KP_EXPORT_SYMBOL(kfunc(strchrnul));
char *kfunc_def(strnchrnul)(const char *s, size_t count, int c) = 0;
KP_EXPORT_SYMBOL(kfunc(strnchrnul));
char *kfunc_def(strrchr)(const char *s, int c) = 0;
KP_EXPORT_SYMBOL(kfunc(strrchr));
char *kfunc_def(strnchr)(const char *s, size_t count, int c) = 0;
KP_EXPORT_SYMBOL(kfunc(strnchr));
char *kfunc_def(skip_spaces)(const char *str) = 0;
KP_EXPORT_SYMBOL(kfunc(skip_spaces));
char *kfunc_def(strim)(char *s) = 0;
KP_EXPORT_SYMBOL(kfunc(strim));
size_t kfunc_def(strlen)(const char *s) = 0;
KP_EXPORT_SYMBOL(kfunc(strlen));
size_t kfunc_def(strnlen)(const char *s, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(strnlen));
size_t kfunc_def(strspn)(const char *s, const char *accept) = 0;
KP_EXPORT_SYMBOL(kfunc(strspn));
size_t kfunc_def(strcspn)(const char *s, const char *reject) = 0;
KP_EXPORT_SYMBOL(kfunc(strcspn));
char *kfunc_def(strpbrk)(const char *cs, const char *ct) = 0;
KP_EXPORT_SYMBOL(kfunc(strpbrk));
char *kfunc_def(strsep)(char **s, const char *ct) = 0;
KP_EXPORT_SYMBOL(kfunc(strsep));
bool kfunc_def(sysfs_streq)(const char *s1, const char *s2) = 0;
KP_EXPORT_SYMBOL(kfunc(sysfs_streq));
int kfunc_def(match_string)(const char *const *array, size_t n, const char *string) = 0;
KP_EXPORT_SYMBOL(kfunc(match_string));
int kfunc_def(__sysfs_match_string)(const char *const *array, size_t n, const char *str) = 0;
KP_EXPORT_SYMBOL(kfunc(__sysfs_match_string));
void *kfunc_def(memset)(void *s, int c, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(memset));
void *kfunc_def(memset16)(uint16_t *s, uint16_t v, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(memset16));
void *kfunc_def(memset32)(uint32_t *s, uint32_t v, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(memset32));
void *kfunc_def(memset64)(uint64_t *s, uint64_t v, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(memset64));
void *kfunc_def(memcpy)(void *dest, const void *src, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(memcpy));
void *kfunc_def(memmove)(void *dest, const void *src, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(memmove));
int kfunc_def(memcmp)(const void *cs, const void *ct, size_t count) = 0;
KP_EXPORT_SYMBOL(kfunc(memcmp));
int kfunc_def(bcmp)(const void *a, const void *b, size_t len) = 0;
KP_EXPORT_SYMBOL(kfunc(bcmp));
void *kfunc_def(memscan)(void *addr, int c, size_t size) = 0;
KP_EXPORT_SYMBOL(kfunc(memscan));
char *kfunc_def(strstr)(const char *s1, const char *s2) = 0;
KP_EXPORT_SYMBOL(kfunc(strstr));
char *kfunc_def(strnstr)(const char *s1, const char *s2, size_t len) = 0;
KP_EXPORT_SYMBOL(kfunc(strnstr));
void *kfunc_def(memchr)(const void *s, int c, size_t n) = 0;
KP_EXPORT_SYMBOL(kfunc(memchr));
void *kfunc_def(memchr_inv)(const void *start, int c, size_t bytes) = 0;
KP_EXPORT_SYMBOL(kfunc(memchr_inv));
char *kfunc_def(strreplace)(char *s, char old, char new) = 0;
KP_EXPORT_SYMBOL(kfunc(strreplace));
void kfunc_def(fortify_panic)(const char *name) = 0;
KP_EXPORT_SYMBOL(kfunc(fortify_panic));

static void _linux_lib_string_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(strncasecmp, name, addr);
    kfunc_match(strcasecmp, name, addr);
    kfunc_match(strcpy, name, addr);
    kfunc_match(strncpy, name, addr);
    kfunc_match(strlcpy, name, addr);
    kfunc_match(strscpy, name, addr);
    kfunc_match(strscpy_pad, name, addr);
    kfunc_match(stpcpy, name, addr);
    kfunc_match(strcat, name, addr);
    kfunc_match(strncat, name, addr);
    kfunc_match(strlcat, name, addr);
    kfunc_match(strcmp, name, addr);
    kfunc_match(strncmp, name, addr);
    kfunc_match(strchr, name, addr);
    kfunc_match(strchrnul, name, addr);
    kfunc_match(strnchrnul, name, addr);
    kfunc_match(strrchr, name, addr);
    kfunc_match(strnchr, name, addr);
    kfunc_match(skip_spaces, name, addr);
    kfunc_match(strim, name, addr);
    kfunc_match(strlen, name, addr);
    kfunc_match(strnlen, name, addr);
    kfunc_match(strspn, name, addr);
    kfunc_match(strcspn, name, addr);
    kfunc_match(strpbrk, name, addr);
    kfunc_match(strsep, name, addr);
    // kfunc_match(sysfs_streq, name, addr);
    kfunc_match(match_string, name, addr);
    // kfunc_match(__sysfs_match_string, name, addr);
    kfunc_match(memset, name, addr);
    // kfunc_match(memset16, name, addr);
    // kfunc_match(memset32, name, addr);
    // kfunc_match(memset64, name, addr);
    kfunc_match(memcpy, name, addr);
    kfunc_match(memmove, name, addr);
    kfunc_match(memcmp, name, addr);
    kfunc_match(bcmp, name, addr);
    kfunc_match(memscan, name, addr);
    kfunc_match(strstr, name, addr);
    kfunc_match(strnstr, name, addr);
    kfunc_match(memchr, name, addr);
    kfunc_match(memchr_inv, name, addr);
    kfunc_match(strreplace, name, addr);
    // kfunc_match(fortify_panic, name, addr);
}

// lib/argv_split.c
void kfunc_def(argv_free)(char **argv) = 0;
KP_EXPORT_SYMBOL(kfunc(argv_free));
char **kfunc_def(argv_split)(gfp_t gfp, const char *str, int *argcp) = 0;
KP_EXPORT_SYMBOL(kfunc(argv_split));

static void _linux_lib_argv_split_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(argv_free, name, addr);
    kfunc_match(argv_split, name, addr);
}

#include <linux/seq_buf.h>
#include <linux/trace_seq.h>

int kfunc_def(seq_buf_to_user)(struct seq_buf *s, char __user *ubuf, int cnt) = 0;
int kfunc_def(trace_seq_to_user)(struct trace_seq *s, char __user *ubuf, int cnt) = 0;
int kfunc_def(xt_data_to_user)(void __user *dst, const void *src, int usersize, int size, int aligned_size) = 0;
int kfunc_def(bits_to_user)(unsigned long *bits, unsigned int maxbit, unsigned int maxlen, void __user *p,
                            int compat) = 0;

static void _linux_lib_seq_buf_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(seq_buf_to_user, name, addr);
    kfunc_match(trace_seq_to_user, name, addr);
    kfunc_match(xt_data_to_user, name, addr);
    // todo: static function
    kfunc_match(bits_to_user, name, addr);
}

// linux/include/kernel.h
int kfunc_def(sprintf)(char *buf, const char *fmt, ...) = 0;
KP_EXPORT_SYMBOL(kfunc(sprintf));
int kfunc_def(vsprintf)(char *buf, const char *fmt, va_list args) = 0;
KP_EXPORT_SYMBOL(kfunc(vsprintf));
int kfunc_def(snprintf)(char *buf, size_t size, const char *fmt, ...) = 0;
KP_EXPORT_SYMBOL(kfunc(snprintf));
int kfunc_def(vsnprintf)(char *buf, size_t size, const char *fmt, va_list args) = 0;
KP_EXPORT_SYMBOL(kfunc(vsnprintf));
int kfunc_def(scnprintf)(char *buf, size_t size, const char *fmt, ...) = 0;
KP_EXPORT_SYMBOL(kfunc(scnprintf));
int kfunc_def(vscnprintf)(char *buf, size_t size, const char *fmt, va_list args) = 0;
KP_EXPORT_SYMBOL(kfunc(vscnprintf));
char *kfunc_def(kasprintf)(gfp_t gfp, const char *fmt, ...) = 0;
KP_EXPORT_SYMBOL(kfunc(kasprintf));
char *kfunc_def(kvasprintf)(gfp_t gfp, const char *fmt, va_list args) = 0;
KP_EXPORT_SYMBOL(kfunc(kvasprintf));
int kfunc_def(sscanf)(const char *buf, const char *fmt, ...) = 0;
KP_EXPORT_SYMBOL(kfunc(sscanf));
int kfunc_def(vsscanf)(const char *buf, const char *fmt, va_list args) = 0;
KP_EXPORT_SYMBOL(kfunc(vsscanf));

static void _linux_include_kernel_sym_match(const char *name, unsigned long addr)
{
    kfunc_match(sprintf, name, addr);
    kfunc_match(vsprintf, name, addr);
    kfunc_match(snprintf, name, addr);
    kfunc_match(vsnprintf, name, addr);
    kfunc_match(scnprintf, name, addr);
    kfunc_match(vscnprintf, name, addr);
    kfunc_match(kasprintf, name, addr);
    kfunc_match(kvasprintf, name, addr);
    kfunc_match(sscanf, name, addr);
    kfunc_match(vsscanf, name, addr);
}

static int _linux_libs_symbol_init(void *data, const char *name, struct module *m, unsigned long addr)
{
    _linux_lib_misc(name, addr);
    _linux_lib_strncpy_from_user_sym_match(name, addr);
    _linux_lib_string_sym_match(name, addr);
    _linux_lib_argv_split_sym_match(name, addr);
    _linux_lib_seq_buf_sym_match(name, addr);
    _linux_include_kernel_sym_match(name, addr);
    return 0;
}

int linux_libs_symbol_init(const char *name, unsigned long addr)
{
#ifdef INIT_USE_KALLSYMS_LOOKUP_NAME
    _linux_libs_symbol_init(0, 0, 0, 0);
#else
    kallsyms_on_each_symbol(_linux_libs_symbol_init, 0);
#endif
    return 0;
}
