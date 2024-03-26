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

#endif