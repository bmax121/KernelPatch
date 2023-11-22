#include "string.h"
#include "ctype.h"

#include <stdint.h>

void *min_memccpy(void *dst, const void *src, int c, size_t n)
{
    char *q = dst;
    const char *p = src;
    char ch;
    while (n--) {
        *q++ = ch = *p++;
        if (ch == (char)c) return q;
    }
    return 0;
}

void *min_memchr(const void *s, int c, size_t n)
{
    const unsigned char *sp = s;
    while (n--) {
        if (*sp == (unsigned char)c) return (void *)sp;
        sp++;
    }
    return 0;
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

void *memcpy(void *dst, const void *src, size_t n)
{
    const char *p = src;
    char *q = dst;
    while (n--) {
        *q++ = *p++;
    }
    return dst;
}

void *min_memmem(const void *haystack, size_t n, const void *needle, size_t m)
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
                if (!min_memcmp(x + 2, y + j + 2, m - 2) && x[0] == y[j]) return (void *)&y[j];
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

void *min_memmove(void *dst, const void *src, size_t n)
{
    const char *p = src;
    char *q = dst;

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

void *min_memrchr(const void *s, int c, size_t n)
{
    const unsigned char *sp = (const unsigned char *)s + n - 1;

    while (n--) {
        if (*sp == (unsigned char)c) return (void *)sp;
        sp--;
    }

    return 0;
}

void *min_memset(void *dst, int c, size_t n)
{
    char *q = dst;
    while (n--) {
        *q++ = c;
    }
    return dst;
}

void min_memswap(void *m1, void *m2, size_t n)
{
    char *p = m1;
    char *q = m2;
    char tmp;

    while (n--) {
        tmp = *p;
        *p = *q;
        *q = tmp;

        p++;
        q++;
    }
}

int min_strcasecmp(const char *s1, const char *s2)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (1) {
        d = min_toupper(ch = *c1++) - min_toupper(*c2++);
        if (d || !ch) break;
    }
    return d;
}

char *min_strcat(char *dst, const char *src)
{
    min_strcpy(min_strchr(dst, '\0'), src);
    return dst;
}

char *min_strchr(const char *s, int c)
{
    while (*s != (char)c) {
        if (!*s) return 0;
        s++;
    }
    return (char *)s;
}

int min_strcmp(const char *s1, const char *s2)
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

char *min_strcpy(char *dst, const char *src)
{
    char *q = dst;
    const char *p = src;
    char ch;
    do {
        *q++ = ch = *p++;
    } while (ch);

    return dst;
}

size_t min_strlcat(char *dst, const char *src, size_t size)
{
    size_t bytes = 0;
    char *q = dst;
    const char *p = src;
    char ch;
    while (bytes < size && *q) {
        q++;
        bytes++;
    }
    if (bytes == size) return (bytes + min_strlen(src));

    while ((ch = *p++)) {
        if (bytes + 1 < size) *q++ = ch;

        bytes++;
    }
    *q = '\0';
    return bytes;
}

size_t min_strlcpy(char *dst, const char *src, size_t size)
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

size_t min_strlen(const char *s)
{
    const char *ss = s;
    while (*ss)
        ss++;
    return ss - s;
}

int min_strncasecmp(const char *s1, const char *s2, size_t n)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (n--) {
        d = min_toupper(ch = *c1++) - min_toupper(*c2++);
        if (d || !ch) break;
    }
    return d;
}

char *min_strncat(char *dst, const char *src, size_t n)
{
    char *q = min_strchr(dst, '\0');
    const char *p = src;
    char ch;
    while (n--) {
        *q++ = ch = *p++;
        if (!ch) return dst;
    }
    *q = '\0';
    return dst;
}

int min_strncmp(const char *s1, const char *s2, size_t n)
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

char *min_strncpy(char *dst, const char *src, size_t n)
{
    char *q = dst;
    const char *p = src;
    char ch;
    while (n) {
        n--;
        *q++ = ch = *p++;
        if (!ch) break;
    }
    min_memset(q, 0, n);
    return dst;
}

size_t min_strnlen(const char *s, size_t maxlen)
{
    const char *ss = s;
    while ((maxlen > 0) && *ss) {
        ss++;
        maxlen--;
    }
    return ss - s;
}

char *min_strpbrk(const char *s1, const char *s2)
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

char *min_strrchr(const char *s, int c)
{
    const char *found = 0;
    while (*s) {
        if (*s == (char)c) found = s;
        s++;
    }
    return (char *)found;
}

char *min_strsep(char **stringp, const char *delim)
{
    char *s = *stringp;
    char *e;
    if (!s) return 0;
    e = min_strpbrk(s, delim);
    if (e) *e++ = '\0';
    *stringp = e;
    return s;
}

size_t min_strspn(const char *s1, const char *s2)
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

char *min_strstr(const char *haystack, const char *needle)
{
    return (char *)min_memmem(haystack, min_strlen(haystack), needle, min_strlen(needle));
}

char *min_strtok(char *s, const char *delim)
{
    static char *holder;
    return min_strtok_r(s, delim, &holder);
}

char *min_strtok_r(char *s, const char *delim, char **holder)
{
    if (s) *holder = s;
    do {
        s = min_strsep(holder, delim);
    } while (s && !*s);
    return s;
}