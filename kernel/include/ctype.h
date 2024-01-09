/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_CTYPE_H_
#define _KP_CTYPE_H_

inline int isupper(int c)
{
    return c >= 'A' && c <= 'Z';
}

inline int islower(int c)
{
    return c >= 'a' && c <= 'z';
}

inline int isalpha(int c)
{
    return islower(c) || isupper(c);
}

inline int isdigit(int c)
{
    return ((unsigned)c - '0') <= 9;
}

inline int isalnum(int c)
{
    return isalpha(c) || isdigit(c);
}

inline int isascii(int c)
{
    return !(c & ~0x7f);
}

inline int isblank(int c)
{
    return (c == '\t') || (c == ' ');
}

inline int iscntrl(int c)
{
    return c < 0x20;
}

inline int isspace(int c)
{
    return c == ' ' || c == '\n' || c == '\t' || c == '\r';
}

inline int isxdigit(int c)
{
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline int toupper(int c)
{
    return islower(c) ? (c & ~32) : c;
}

inline int tolower(int c)
{
    return isupper(c) ? (c | 32) : c;
}

#endif