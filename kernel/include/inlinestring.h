#ifndef _KP_INLINESTRING_H_
#define _KP_INLINESTRING_H_

#include <stdint.h>
#include <ctype.h>

static inline void *inline_memccpy(void *dst, const void *src, int c, size_t n)
{
    char *q = (char *)dst;
    const char *p = (const char *)src;
    char ch;
    while (n--) {
        *q++ = ch = *p++;
        if (ch == (char)c) return q;
    }
    return 0;
}

static inline void *inline_memchr(const void *s, int c, size_t n)
{
    const unsigned char *sp = (const unsigned char *)s;
    while (n--) {
        if (*sp == (unsigned char)c) return (void *)sp;
        sp++;
    }
    return 0;
}

static inline int inline_memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    int d = 0;
    while (n--) {
        d = (int)*c1++ - (int)*c2++;
        if (d) break;
    }
    return d;
}

static inline void *inline_memcpy(void *dst, const void *src, size_t n)
{
    const char *p = (const char *)src;
    char *q = (char *)dst;
    while (n--) {
        *q++ = *p++;
    }
    return dst;
}

static inline void *inline_memmove(void *dst, const void *src, size_t n)
{
    const char *p = (const char *)src;
    char *q = (char *)dst;

    if (q < p) {
        while (n--) {
            *q++ = *p++;
        }
    } else {
        p += n;
        q += n;
        while (n--) {
            *--q = *--p;
        }
    }
    return dst;
}

static inline void *inline_memrchr(const void *s, int c, size_t n)
{
    const unsigned char *sp = (const unsigned char *)s + n - 1;

    while (n--) {
        if (*sp == (unsigned char)c) return (void *)sp;
        sp--;
    }

    return 0;
}

static inline void *inline_memset(void *dst, int c, size_t n)
{
    char *q = (char *)dst;
    while (n--) {
        *q++ = c;
    }
    return dst;
}

static inline void inline_memswap(void *m1, void *m2, size_t n)
{
    char *p = (char *)m1;
    char *q = (char *)m2;
    char tmp;

    while (n--) {
        tmp = *p;
        *p = *q;
        *q = tmp;

        p++;
        q++;
    }
}

static inline int inline_strcasecmp(const char *s1, const char *s2)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (1) {
        d = toupper(ch = *c1++) - toupper(*c2++);
        if (d || !ch) break;
    }
    return d;
}

static inline char *inline_strchr(const char *s, int c)
{
    while (*s != (char)c) {
        if (!*s) return 0;
        s++;
    }
    return (char *)s;
}

static inline int inline_strcmp(const char *s1, const char *s2)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (1) {
        d = (int)(ch = *c1++) - (int)*c2++;
        if (d || !ch) break;
    }
    return d;
}

static inline char *inline_strcpy(char *dst, const char *src)
{
    char *q = dst;
    const char *p = src;
    char ch;
    do {
        *q++ = ch = *p++;
    } while (ch);

    return dst;
}

static inline size_t inline_strlcpy(char *dst, const char *src, size_t size)
{
    size_t bytes = 0;
    char *q = dst;
    const char *p = src;
    char ch;

    while ((ch = *p++)) {
        if (bytes + 1 < size) *q++ = ch;

        bytes++;
    }
    if (size) *q = '\0';
    return bytes;
}

static inline size_t inline_strlen(const char *s)
{
    const char *ss = s;
    while (*ss)
        ss++;
    return ss - s;
}

static inline int inline_strncasecmp(const char *s1, const char *s2, size_t n)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (n--) {
        d = toupper(ch = *c1++) - toupper(*c2++);
        if (d || !ch) break;
    }
    return d;
}

static inline char *inline_strncat(char *dst, const char *src, size_t n)
{
    char *q = inline_strchr(dst, '\0');
    const char *p = src;
    char ch;
    while (n--) {
        *q++ = ch = *p++;
        if (!ch) return dst;
    }
    *q = '\0';
    return dst;
}

static inline int inline_strncmp(const char *s1, const char *s2, size_t n)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (n--) {
        d = (int)(ch = *c1++) - (int)*c2++;
        if (d || !ch) break;
    }
    return d;
}

static inline char *inline_strncpy(char *dst, const char *src, size_t n)
{
    char *q = dst;
    const char *p = src;
    char ch;
    while (n) {
        n--;
        *q++ = ch = *p++;
        if (!ch) break;
    }
    inline_memset(q, 0, n);
    return dst;
}

static inline size_t inline_strnlen(const char *s, size_t maxlen)
{
    const char *ss = s;
    while ((maxlen > 0) && *ss) {
        ss++;
        maxlen--;
    }
    return ss - s;
}

static inline char *inline_strpbrk(const char *s1, const char *s2)
{
    const char *c = s2;
    if (!*s1) return (char *)0;
    while (*s1) {
        for (c = s2; *c; c++) {
            if (*s1 == *c) break;
        }
        if (*c) break;
        s1++;
    }
    if (*c == '\0') s1 = 0;
    return (char *)s1;
}

static inline char *inline_strrchr(const char *s, int c)
{
    const char *found = 0;
    while (*s) {
        if (*s == (char)c) found = s;
        s++;
    }
    return (char *)found;
}

static inline char *inline_strsep(char **stringp, const char *delim)
{
    char *s = *stringp;
    char *e;
    if (!s) return 0;
    e = inline_strpbrk(s, delim);
    if (e) *e++ = '\0';
    *stringp = e;
    return s;
}

static inline size_t inline_strspn(const char *s1, const char *s2)
{
    const char *s = s1;
    const char *c;
    while (*s1) {
        for (c = s2; *c; c++) {
            if (*s1 == *c) break;
        }
        if (*c == '\0') break;
        s1++;
    }
    return s1 - s;
}

#endif