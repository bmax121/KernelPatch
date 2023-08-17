#ifndef _KP_STRING_H_
#define _KP_STRING_H_

#include <stdint.h>

void *min_memccpy(void *, const void *, int, size_t);
void *min_memchr(const void *, int, size_t);
void *min_memrchr(const void *, int, size_t);
int min_memcmp(const void *, const void *, size_t);
void *min_memcpy(void *, const void *, size_t);
void *min_memmove(void *, const void *, size_t);
void *min_memset(void *, int, size_t);
void *min_memmem(const void *, size_t, const void *, size_t);
void min_memswap(void *, void *, size_t);
void min_bzero(void *, size_t);
int min_strcasecmp(const char *, const char *);
int min_strncasecmp(const char *, const char *, size_t);
char *min_strcat(char *, const char *);
char *min_strchr(const char *, int);
char *min_index(const char *, int);
char *min_strrchr(const char *, int);
char *min_rindex(const char *, int);
int min_strcmp(const char *, const char *);
char *min_strcpy(char *, const char *);
size_t min_strcspn(const char *, const char *);
char *min_strdup(const char *);
char *min_strndup(const char *, size_t);
size_t min_strlen(const char *);
size_t min_strnlen(const char *, size_t);
char *min_strncat(char *, const char *, size_t);
size_t min_strlcat(char *, const char *, size_t);
int min_strncmp(const char *, const char *, size_t);
char *min_strncpy(char *, const char *, size_t);
size_t min_strlcpy(char *, const char *, size_t);
char *min_strpbrk(const char *, const char *);
char *min_strsep(char **, const char *);
size_t min_strspn(const char *, const char *);
char *min_strstr(const char *, const char *);
char *min_strtok(char *, const char *);
char *min_strtok_r(char *, const char *, char **);

inline static int min_strcoll(const char *s1, const char *s2)
{
    return min_strcmp(s1, s2);
}

inline static size_t min_strxfrm(char *dest, const char *src, size_t n)
{
    min_strncpy(dest, src, n);
    return min_strlen(src);
}

#endif