#ifndef _LINUX_TRACE_SEQ_H
#define _LINUX_TRACE_SEQ_H

#include <ktypes.h>
#include <ksyms.h>
#include <stdarg.h>

// 3.18
// struct trace_seq
// {
//     unsigned char buffer[PAGE_SIZE];
//     unsigned int len;
//     unsigned int readpos;
//     int full;
// };

// 4.4
// struct trace_seq {
// 	char			buffer[PAGE_SIZE];
// 	struct seq_buf		seq;
// 	int			full;
// };

// static inline void trace_seq_init(struct trace_seq *s)
// {
//     s->len = 0;
//     s->readpos = 0;
//     s->full = 0;
// }

struct trace_seq;

extern int kfunc_def(trace_seq_printf)(struct trace_seq *s, const char *fmt, ...);
extern int kfunc_def(trace_seq_to_user)(struct trace_seq *s, char __user *ubuf, int cnt);
extern int kfunc_def(trace_seq_puts)(struct trace_seq *s, const char *str);
extern int kfunc_def(trace_seq_putc)(struct trace_seq *s, unsigned char c);
extern int kfunc_def(trace_seq_putmem)(struct trace_seq *s, const void *mem, unsigned int len);
extern int kfunc_def(trace_seq_putmem_hex)(struct trace_seq *s, const void *mem, unsigned int len);
extern int kfunc_def(trace_seq_bitmask)(struct trace_seq *s, const unsigned long *maskp, int nmaskbits);

static inline int trace_seq_printf(struct trace_seq *s, const char *fmt, ...)
{
    if (!kfunc(trace_seq_printf)) {
        kfunc_not_found();
        return 0;
    }
    va_list args;
    va_start(args, fmt);
    int rc = kfunc(trace_seq_printf)(s, fmt, args);
    va_end(args);
    return rc;
}
static inline int trace_seq_to_user(struct trace_seq *s, char __user *ubuf, int cnt)
{
    kfunc_call(trace_seq_to_user, s, ubuf, cnt);
    kfunc_not_found();
    return 0;
}
static inline int trace_seq_puts(struct trace_seq *s, const char *str)
{
    kfunc_call(trace_seq_puts, s, str);
    kfunc_not_found();
    return 0;
}
static inline int trace_seq_putc(struct trace_seq *s, unsigned char c)
{
    kfunc_call(trace_seq_putc, s, c);
    kfunc_not_found();
    return 0;
}
static inline int trace_seq_putmem(struct trace_seq *s, const void *mem, unsigned int len)
{
    kfunc_call(trace_seq_putmem, s, mem, len);
    kfunc_not_found();
    return 0;
}
static inline int trace_seq_putmem_hex(struct trace_seq *s, const void *mem, unsigned int len)
{
    kfunc_call(trace_seq_putmem_hex, s, mem, len);
    kfunc_not_found();
    return 0;
}
static inline int trace_seq_bitmask(struct trace_seq *s, const unsigned long *maskp, int nmaskbits)
{
    kfunc_call(trace_seq_bitmask, s, maskp, nmaskbits);
    kfunc_not_found();
    return 0;
}

#endif