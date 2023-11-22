#include <stdint.h>
#include <stddef.h>

#include "stdlib.h"
#include "ctype.h"
#include "string.h"

static inline int digitval(int ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    } else if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A' + 10;
    } else if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 10;
    } else {
        return -1;
    }
}

uintmax_t strntoumax(const char *nptr, char **endptr, int base, size_t n)
{
    int minus = 0;
    uintmax_t v = 0;
    int d;
    while (n && min_isspace((unsigned char)*nptr)) {
        nptr++;
        n--;
    }
    /* Single optional + or - */
    if (n) {
        char c = *nptr;
        if (c == '-' || c == '+') {
            minus = (c == '-');
            nptr++;
            n--;
        }
    }

    if (base == 0) {
        if (n >= 2 && nptr[0] == '0' && (nptr[1] == 'x' || nptr[1] == 'X')) {
            n -= 2;
            nptr += 2;
            base = 16;
        } else if (n >= 1 && nptr[0] == '0') {
            n--;
            nptr++;
            base = 8;
        } else {
            base = 10;
        }
    } else if (base == 16) {
        if (n >= 2 && nptr[0] == '0' && (nptr[1] == 'x' || nptr[1] == 'X')) {
            n -= 2;
            nptr += 2;
        }
    }
    while (n && (d = digitval(*nptr)) >= 0 && d < base) {
        v = v * base + d;
        n--;
        nptr++;
    }
    if (endptr) *endptr = (char *)nptr;
    return minus ? -v : v;
}

intmax_t strntoimax(const char *nptr, char **endptr, int base, size_t n)
{
    return (intmax_t)strntoumax(nptr, endptr, base, n);
}

int atoi(const char *nptr)
{
    return (int)strntoumax(nptr, (char **)NULL, 10, ~(size_t)0);
}

long atol(const char *nptr)
{
    return (long)strntoumax(nptr, (char **)NULL, 10, ~(size_t)0);
}

void *bsearch(const void *key, const void *base, size_t nmemb, size_t size, min_comparefunc_t cmp)
{
    while (nmemb) {
        size_t mididx = nmemb / 2;
        const void *midobj = (const char *)base + mididx * size;
        int diff = cmp(key, midobj);

        if (diff == 0) return (void *)midobj;

        if (diff > 0) {
            base = (const char *)midobj + size;
            nmemb -= mididx + 1;
        } else
            nmemb = mididx;
    }

    return NULL;
}

static inline size_t newgap(size_t gap)
{
    gap = (gap * 10) / 13;
    if (gap == 9 || gap == 10) gap = 11;

    if (gap < 1) gap = 1;
    return gap;
}

void qsort(void *base, size_t nmemb, size_t size, min_comparefunc_t cmp)
{
    size_t gap = nmemb;
    size_t i, j;
    char *p1, *p2;
    int swapped;

    if (!nmemb) return;

    do {
        gap = newgap(gap);
        swapped = 0;

        for (i = 0, p1 = base; i < nmemb - gap; i++, p1 += size) {
            j = i + gap;
            if (cmp(p1, p2 = (char *)base + j * size) > 0) {
                min_memswap(p1, p2, size);
                swapped = 1;
            }
        }
    } while (gap > 1 || swapped);
}

signed long strtol(const char *nptr, char **endptr, int base)
{
    return (signed long)strntoumax(nptr, endptr, base, ~(size_t)0);
}

signed long long strtoll(const char *nptr, char **endptr, int base)
{
    return (signed long long)strntoumax(nptr, endptr, base, ~(size_t)0);
}

unsigned long strtoul(const char *nptr, char **endptr, int base)
{
    return (signed long)strntoumax(nptr, endptr, base, ~(size_t)0);
}

unsigned long long strtoull(const char *nptr, char **endptr, int base)
{
    return (signed long long)strntoumax(nptr, endptr, base, ~(size_t)0);
}

uintmax_t strtoumax(const char *nptr, char **endptr, int base)
{
    return (uintmax_t)strntoumax(nptr, endptr, base, ~(size_t)0);
}