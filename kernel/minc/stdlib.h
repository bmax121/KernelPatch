#ifndef _KP_STDLIB_H_
#define _KP_STDLIB_H_

#include <stdbool.h>
#include <stdint.h>

inline int abs(int n)
{
    return (n < 0) ? -n : n;
}

int atoi(const char *);
long atol(const char *);

inline long labs(long n)
{
    return (n < 0L) ? -n : n;
}

inline long long llabs(long long n)
{
    return (n < 0LL) ? -n : n;
}

long strtol(const char *, char **, int);
long long strtoll(const char *, char **, int);
unsigned long strtoul(const char *, char **, int);
unsigned long long strtoull(const char *, char **, int);

typedef int (*min_comparefunc_t)(const void *, const void *);

void *bsearch(const void *, const void *, size_t, size_t, min_comparefunc_t);
void qsort(void *, size_t, size_t, min_comparefunc_t);

#endif