#ifndef _KP_CTYPE_H_
#define _KP_CTYPE_H_

inline int min_isupper(int c)
{
    return c >= 'A' && c <= 'Z';
}

inline int min_islower(int c)
{
    return c >= 'a' && c <= 'z';
}

inline int min_isalpha(int c)
{
    return min_islower(c) || min_isupper(c);
}

inline int min_isdigit(int c)
{
    return ((unsigned)c - '0') <= 9;
}

inline int min_isalnum(int c)
{
    return min_isalpha(c) || min_isdigit(c);
}

inline int min_isascii(int c)
{
    return !(c & ~0x7f);
}

inline int min_isblank(int c)
{
    return (c == '\t') || (c == ' ');
}

inline int min_iscntrl(int c)
{
    return c < 0x20;
}

inline int min_isspace(int c)
{
    return c == ' ' || c == '\n' || c == '\t' || c == '\r';
}

inline int min_isxdigit(int c)
{
    return min_isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline int min_toupper(int c)
{
    return min_islower(c) ? (c & ~32) : c;
}

inline int min_tolower(int c)
{
    return min_isupper(c) ? (c | 32) : c;
}

#endif