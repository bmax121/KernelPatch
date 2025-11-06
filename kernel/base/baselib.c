/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <baselib.h>

void *lib_memccpy(void *dst, const void *src, int c, size_t n)
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

void *lib_memchr(const void *s, int c, size_t n)
{
    const unsigned char *sp = (const unsigned char *)s;
    while (n--) {
        if (*sp == (unsigned char)c) return (void *)sp;
        sp++;
    }
    return 0;
}

int lib_memcmp(const void *s1, const void *s2, size_t n)
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

void *lib_memcpy(void *dst, const void *src, size_t n)
{
    const char *p = (const char *)src;
    char *q = (char *)dst;
    while (n--) {
        *q++ = *p++;
    }
    return dst;
}

void *lib_memmove(void *dst, const void *src, size_t n)
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

void *lib_memrchr(const void *s, int c, size_t n)
{
    const unsigned char *sp = (const unsigned char *)s + n - 1;

    while (n--) {
        if (*sp == (unsigned char)c) return (void *)sp;
        sp--;
    }

    return 0;
}

void *lib_memset(void *dst, int c, size_t n)
{
    char *q = (char *)dst;
    while (n--) {
        *q++ = c;
    }
    return dst;
}

void lib_memswap(void *m1, void *m2, size_t n)
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

int min_memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *c1 = s1, *c2 = s2;
    int d = 0;
    while (n--) {
        d = (int)*c1++ - (int)*c2++;
        if (d) break;
    }
    return d;
}

void *lib_memmem(const void *haystack, size_t n, const void *needle, size_t m)
{
    const unsigned char *y = (const unsigned char *)haystack;
    const unsigned char *x = (const unsigned char *)needle;

    size_t j, k, l;

    if (m > n || !m || !n) return 0;

    if (1 != m) {
        if (x[0] == x[1]) {
            k = 2;
            l = 1;
        } else {
            k = 1;
            l = 2;
        }

        j = 0;
        while (j <= n - m) {
            if (x[1] != y[j + 1]) {
                j += k;
            } else {
                if (!lib_memcmp(x + 2, y + j + 2, m - 2) && x[0] == y[j]) return (void *)&y[j];
                j += l;
            }
        }
    } else
        do {
            if (*y == *x) return (void *)y;
            y++;
        } while (--n);
    return 0;
}

int lib_strcasecmp(const char *s1, const char *s2)
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

char *lib_strchr(const char *s, int c)
{
    while (*s != (char)c) {
        if (!*s) return 0;
        s++;
    }
    return (char *)s;
}

int lib_strcmp(const char *s1, const char *s2)
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

char *lib_strcpy(char *dst, const char *src)
{
    char *q = dst;
    const char *p = src;
    char ch;
    do {
        *q++ = ch = *p++;
    } while (ch);

    return dst;
}

size_t lib_strlcpy(char *dst, const char *src, size_t size)
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

size_t lib_strlen(const char *s)
{
    const char *ss = s;
    while (*ss)
        ss++;
    return ss - s;
}

int lib_strncasecmp(const char *s1, const char *s2, size_t n)
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

char *lib_strncat(char *dst, const char *src, size_t n)
{
    char *q = lib_strchr(dst, '\0');
    const char *p = src;
    char ch;
    while (n--) {
        *q++ = ch = *p++;
        if (!ch) return dst;
    }
    // *q = '\0';
    return dst;
}

char *lib_strcat(char *dst, const char *src)
{
    lib_strcpy(lib_strchr(dst, '\0'), src);
    return dst;
}

int lib_strncmp(const char *s1, const char *s2, size_t n)
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

char *lib_strncpy(char *dst, const char *src, size_t n)
{
    char *q = dst;
    const char *p = src;
    char ch;
    while (n) {
        n--;
        *q++ = ch = *p++;
        if (!ch) break;
    }
    // *q = '\0';
    return dst;
}

size_t lib_strnlen(const char *s, size_t maxlen)
{
    const char *ss = s;
    while ((maxlen > 0) && *ss) {
        ss++;
        maxlen--;
    }
    return ss - s;
}

char *lib_strpbrk(const char *s1, const char *s2)
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

char *lib_strrchr(const char *s, int c)
{
    const char *found = 0;
    while (*s) {
        if (*s == (char)c) found = s;
        s++;
    }
    return (char *)found;
}

char *lib_strsep(char **stringp, const char *delim)
{
    char *s = *stringp;
    char *e;
    if (!s) return 0;
    e = lib_strpbrk(s, delim);
    if (e) *e++ = '\0';
    *stringp = e;
    return s;
}

size_t lib_strspn(const char *s1, const char *s2)
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

char *lib_strstr(const char *haystack, const char *needle)
{
    return (char *)lib_memmem(haystack, lib_strlen(haystack), needle, lib_strlen(needle));
}

void *memset(void *dst, int c, size_t n)
{
    return lib_memset(dst, c, n);
}
