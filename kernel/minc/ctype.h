#ifndef _KP_CTYPE_H_
#define _KP_CTYPE_H_

inline int min_isupper(int __c)
{
    return __c >= 'A' && __c <= 'Z';
}

inline int min_islower(int __c)
{
    return __c >= 'a' && __c <= 'z';
}

inline int min_isalpha(int __c)
{
    return min_islower(__c) || min_isupper(__c);
}

inline int min_isdigit(int __c)
{
    return ((unsigned)__c - '0') <= 9;
}

inline int min_isalnum(int __c)
{
    return min_isalpha(__c) || min_isdigit(__c);
}

inline int min_isascii(int __c)
{
    return !(__c & ~0x7f);
}

inline int min_isblank(int __c)
{
    return (__c == '\t') || (__c == ' ');
}

inline int min_iscntrl(int __c)
{
    return __c < 0x20;
}

inline int min_isspace(int __c)
{
    return __c == ' ' || __c == '\n' || __c == '\t' || __c == '\r';
}

inline int min_isxdigit(int __c)
{
    return min_isdigit(__c) || (__c >= 'a' && __c <= 'f') || (__c >= 'A' && __c <= 'F');
}

inline int min_toupper(int __c)
{
    return min_islower(__c) ? (__c & ~32) : __c;
}

inline int min_tolower(int __c)
{
    return min_isupper(__c) ? (__c | 32) : __c;
}

#endif