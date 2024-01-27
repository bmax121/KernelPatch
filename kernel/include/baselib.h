/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_BASELIB_H_
#define _KP_BASELIB_H_

#include <stdint.h>
#include <ctype.h>

void *lib_memccpy(void *dst, const void *src, int c, size_t n);
void *lib_memchr(const void *s, int c, size_t n);
int lib_memcmp(const void *s1, const void *s2, size_t n);
void *lib_memcpy(void *dst, const void *src, size_t n);
void *lib_memmove(void *dst, const void *src, size_t n);
void *lib_memrchr(const void *s, int c, size_t n);
void *lib_memset(void *dst, int c, size_t n);
void lib_memswap(void *m1, void *m2, size_t n);
int lib_memcmp(const void *s1, const void *s2, size_t n);
void *lib_memmem(const void *haystack, size_t n, const void *needle, size_t m);

int lib_strcasecmp(const char *s1, const char *s2);
char *lib_strchr(const char *s, int c);
int lib_strcmp(const char *s1, const char *s2);
char *lib_strcpy(char *dst, const char *src);
size_t lib_strlcpy(char *dst, const char *src, size_t size);
size_t lib_strlen(const char *s);
int lib_strncasecmp(const char *s1, const char *s2, size_t n);
char *lib_strncat(char *dst, const char *src, size_t n);
char *lib_strcat(char *dst, const char *src);
int lib_strncmp(const char *s1, const char *s2, size_t n);
char *lib_strncpy(char *dst, const char *src, size_t n);
size_t lib_strnlen(const char *s, size_t maxlen);
char *lib_strpbrk(const char *s1, const char *s2);
char *lib_strrchr(const char *s, int c);
char *lib_strsep(char **stringp, const char *delim);
size_t lib_strspn(const char *s1, const char *s2);

#endif