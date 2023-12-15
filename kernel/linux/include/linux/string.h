#ifndef _LINUX_STRING_H_
#define _LINUX_STRING_H_

#include <ktypes.h>
#include <ksyms.h>
#include <linux/gfp.h>
#include <linux/panic.h>

extern void kfunc_def(kfree_const)(const void *x);
extern char *kfunc_def(kstrdup)(const char *s, gfp_t gfp);
extern const char *kfunc_def(kstrdup_const)(const char *s, gfp_t gfp);
extern char *kfunc_def(kstrndup)(const char *s, size_t len, gfp_t gfp);
extern void *kfunc_def(memdup_user)(const void __user *src, size_t len);
extern void *kfunc_def(kmemdup)(const void *src, size_t len, gfp_t gfp);
extern char *kfunc_def(kmemdup_nul)(const char *s, size_t len, gfp_t gfp);
extern char **kfunc_def(argv_split)(gfp_t gfp, const char *str, int *argcp);
extern void kfunc_def(argv_free)(char **argv);
extern int kfunc_def(kstrtobool)(const char *s, bool *res);

extern int kfunc_def(strncasecmp)(const char *s1, const char *s2, size_t len);
extern int kfunc_def(strcasecmp)(const char *s1, const char *s2);
extern char *kfunc_def(strcpy)(char *dest, const char *src);
extern char *kfunc_def(strncpy)(char *dest, const char *src, size_t count);
extern size_t kfunc_def(strlcpy)(char *dest, const char *src, size_t size);
extern ssize_t kfunc_def(strscpy)(char *dest, const char *src, size_t count);
extern ssize_t kfunc_def(strscpy_pad)(char *dest, const char *src, size_t count);
extern char *kfunc_def(stpcpy)(char *__restrict__ dest, const char *__restrict__ src);
extern char *kfunc_def(strcat)(char *dest, const char *src);
extern char *kfunc_def(strncat)(char *dest, const char *src, size_t count);
extern size_t kfunc_def(strlcat)(char *dest, const char *src, size_t count);
extern int kfunc_def(strcmp)(const char *cs, const char *ct);
extern int kfunc_def(strncmp)(const char *cs, const char *ct, size_t count);
extern char *kfunc_def(strchr)(const char *s, int c);
extern char *kfunc_def(strchrnul)(const char *s, int c);
extern char *kfunc_def(strnchrnul)(const char *s, size_t count, int c);
extern char *kfunc_def(strrchr)(const char *s, int c);
extern char *kfunc_def(strnchr)(const char *s, size_t count, int c);
extern char *kfunc_def(skip_spaces)(const char *str);
extern char *kfunc_def(strim)(char *s);
extern size_t kfunc_def(strlen)(const char *s);
extern size_t kfunc_def(strnlen)(const char *s, size_t count);
extern size_t kfunc_def(strspn)(const char *s, const char *accept);
extern size_t kfunc_def(strcspn)(const char *s, const char *reject);
extern char *kfunc_def(strpbrk)(const char *cs, const char *ct);
extern char *kfunc_def(strsep)(char **s, const char *ct);
extern bool kfunc_def(sysfs_streq)(const char *s1, const char *s2);
extern int kfunc_def(match_string)(const char *const *array, size_t n, const char *string);
extern int kfunc_def(__sysfs_match_string)(const char *const *array, size_t n, const char *str);
extern void *kfunc_def(memset)(void *s, int c, size_t count);
extern void *kfunc_def(memset16)(uint16_t *s, uint16_t v, size_t count);
extern void *kfunc_def(memset32)(uint32_t *s, uint32_t v, size_t count);
extern void *kfunc_def(memset64)(uint64_t *s, uint64_t v, size_t count);
extern void *kfunc_def(memcpy)(void *dest, const void *src, size_t count);
extern void *kfunc_def(memmove)(void *dest, const void *src, size_t count);
extern int kfunc_def(memcmp)(const void *cs, const void *ct, size_t count);
extern int kfunc_def(bcmp)(const void *a, const void *b, size_t len);
extern void *kfunc_def(memscan)(void *addr, int c, size_t size);
extern char *kfunc_def(strstr)(const char *s1, const char *s2);
extern char *kfunc_def(strnstr)(const char *s1, const char *s2, size_t len);
extern void *kfunc_def(memchr)(const void *s, int c, size_t n);
extern void *kfunc_def(memchr_inv)(const void *start, int c, size_t bytes);
extern char *kfunc_def(strreplace)(char *s, char old, char new);
extern void kfunc_def(fortify_panic)(const char *name);

static inline void kfree_const(const void *x)
{
    kfunc_direct_call(kfree_const, x);
}

static inline char *kstrdup(const char *s, gfp_t gfp)
{
    kfunc_direct_call(kstrdup, s, gfp);
}

static inline const char *kstrdup_const(const char *s, gfp_t gfp)
{
    kfunc_direct_call(kstrdup_const, s, gfp);
}

static inline char *kstrndup(const char *s, size_t len, gfp_t gfp)
{
    kfunc_direct_call(kstrndup, s, len, gfp);
}

static inline void *kmemdup(const void *src, size_t len, gfp_t gfp)
{
    kfunc_direct_call(kmemdup, src, len, gfp);
}

static inline char *kmemdup_nul(const char *s, size_t len, gfp_t gfp)
{
    kfunc_direct_call(kmemdup_nul, s, len, gfp);
}

static inline void *memdup_user(const void __user *src, size_t len)
{
    kfunc_direct_call(memdup_user, src, len);
}

static inline char **argv_split(gfp_t gfp, const char *str, int *argcp)
{
    kfunc_direct_call(argv_split, gfp, str, argcp);
}

static inline void argv_free(char **argv)
{
    kfunc_direct_call(argv_free, argv);
}

static inline int kstrtobool(const char *s, bool *res)
{
    kfunc_direct_call(kstrtobool, s, res);
}

static inline int strncasecmp(const char *s1, const char *s2, size_t len)
{
    kfunc_direct_call(strncasecmp, s1, s2, len);
}

static inline int strcasecmp(const char *s1, const char *s2)
{
    kfunc_direct_call(strcasecmp, s1, s2);
}

static inline char *strcpy(char *dest, const char *src)
{
    kfunc_direct_call(strcpy, dest, src);
}

static inline char *strncpy(char *dest, const char *src, size_t count)
{
    kfunc_direct_call(strncpy, dest, src, count);
}

static inline size_t strlcpy(char *dest, const char *src, size_t size)
{
    kfunc_direct_call(strlcpy, dest, src, size);
}

static inline ssize_t strscpy(char *dest, const char *src, size_t count)
{
    kfunc_direct_call(strscpy, dest, src, count);
}

static inline ssize_t strscpy_pad(char *dest, const char *src, size_t count)
{
    kfunc_direct_call(strscpy_pad, dest, src, count);
}

static inline char *stpcpy(char *__restrict__ dest, const char *__restrict__ src)
{
    kfunc_direct_call(stpcpy, dest, src);
}

static inline char *strcat(char *dest, const char *src)
{
    kfunc_direct_call(strcat, dest, src);
}

static inline char *strncat(char *dest, const char *src, size_t count)
{
    kfunc_direct_call(strncat, dest, src, count);
}

static inline size_t strlcat(char *dest, const char *src, size_t count)
{
    kfunc_direct_call(strlcat, dest, src, count);
}

static inline int strcmp(const char *cs, const char *ct)
{
    kfunc_direct_call(strcmp, cs, ct);
}

static inline int strncmp(const char *cs, const char *ct, size_t count)
{
    kfunc_direct_call(strncmp, cs, ct, count);
}

static inline char *strchr(const char *s, int c)
{
    kfunc_direct_call(strchr, s, c);
}

static inline char *strchrnul(const char *s, int c)
{
    kfunc_direct_call(strchrnul, s, c);
}

static inline char *strnchrnul(const char *s, size_t count, int c)
{
    kfunc_direct_call(strnchrnul, s, count, c);
}

static inline char *strrchr(const char *s, int c)
{
    kfunc_direct_call(strrchr, s, c);
}

static inline char *strnchr(const char *s, size_t count, int c)
{
    kfunc_direct_call(strnchr, s, count, c);
}

static inline char *skip_spaces(const char *str)
{
    kfunc_direct_call(skip_spaces, str);
}

static inline char *strim(char *s)
{
    kfunc_direct_call(strim, s);
}

static inline size_t strlen(const char *s)
{
    kfunc_direct_call(strlen, s);
}

static inline size_t strnlen(const char *s, size_t count)
{
    kfunc_direct_call(strnlen, s, count);
}

static inline size_t strspn(const char *s, const char *accept)
{
    kfunc_direct_call(strspn, s, accept);
}

static inline size_t strcspn(const char *s, const char *reject)
{
    kfunc_direct_call(strcspn, s, reject);
}

static inline char *strpbrk(const char *cs, const char *ct)
{
    kfunc_direct_call(strpbrk, cs, ct);
}

static inline char *strsep(char **s, const char *ct)
{
    kfunc_direct_call(strsep, s, ct);
}

static inline bool sysfs_streq(const char *s1, const char *s2)
{
    kfunc_direct_call(sysfs_streq, s1, s2);
}

static inline int match_string(const char *const *array, size_t n, const char *string)
{
    kfunc_direct_call(match_string, array, n, string);
}

static inline int __sysfs_match_string(const char *const *array, size_t n, const char *str)
{
    kfunc_direct_call(__sysfs_match_string, array, n, str);
}

static inline void *memset(void *s, int c, size_t count)
{
    kfunc_direct_call(memset, s, c, count);
}

static inline void *memset16(uint16_t *s, uint16_t v, size_t count)
{
    kfunc_direct_call(memset16, s, v, count);
}

static inline void *memset32(uint32_t *s, uint32_t v, size_t count)
{
    kfunc_direct_call(memset32, s, v, count);
}

static inline void *memset64(uint64_t *s, uint64_t v, size_t count)
{
    kfunc_direct_call(memset64, s, v, count);
}

static inline void *memcpy(void *dest, const void *src, size_t count)
{
    kfunc_direct_call(memcpy, dest, src, count);
}

static inline void *memmove(void *dest, const void *src, size_t count)
{
    kfunc_direct_call(memmove, dest, src, count);
}

static inline int memcmp(const void *cs, const void *ct, size_t count)
{
    kfunc_direct_call(memcmp, cs, ct, count);
}

static inline int bcmp(const void *a, const void *b, size_t len)
{
    kfunc_direct_call(bcmp, a, b, len);
}

static inline void *memscan(void *addr, int c, size_t size)
{
    kfunc_direct_call(memscan, addr, c, size);
}

static inline char *strstr(const char *s1, const char *s2)
{
    kfunc_direct_call(strstr, s1, s2);
}

static inline char *strnstr(const char *s1, const char *s2, size_t len)
{
    kfunc_direct_call(strnstr, s1, s2, len);
}

static inline void *memchr(const void *s, int c, size_t n)
{
    kfunc_direct_call(memchr, s, c, n);
}

static inline void *memchr_inv(const void *start, int c, size_t bytes)
{
    kfunc_direct_call(memchr_inv, start, c, bytes);
}

static inline char *strreplace(char *s, char old, char new)
{
    kfunc_direct_call(strreplace, s, old, new);
}

static inline void fortify_panic(const char *name)
{
    kfunc_direct_call(fortify_panic, name);
}

#endif