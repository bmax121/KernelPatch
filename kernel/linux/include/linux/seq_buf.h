/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SEQ_BUF_H
#define _LINUX_SEQ_BUF_H

#include <ktypes.h>
#include <ksyms.h>
#include <stdarg.h>
#include <linux/trace_seq.h>

struct seq_buf
{
    char *buffer;
    size_t size;
    size_t len;
    loff_t readpos;
};

static inline void seq_buf_clear(struct seq_buf *s)
{
    s->len = 0;
    s->readpos = 0;
}

extern int kfunc_def(seq_buf_printf)(struct seq_buf *s, const char *fmt, ...);
extern int kfunc_def(seq_buf_to_user)(struct seq_buf *s, char __user *ubuf, int cnt);
extern int kfunc_def(seq_buf_puts)(struct seq_buf *s, const char *str);
extern int kfunc_def(seq_buf_putc)(struct seq_buf *s, unsigned char c);
extern int kfunc_def(seq_buf_putmem)(struct seq_buf *s, const void *mem, unsigned int len);
extern int kfunc_def(seq_buf_putmem_hex)(struct seq_buf *s, const void *mem, unsigned int len);
extern int kfunc_def(seq_buf_bitmask)(struct seq_buf *s, const unsigned long *maskp, int nmaskbits);

static inline int seq_buf_printf(struct seq_buf *s, const char *fmt, ...)
{
    if (!kfunc(seq_buf_printf)) {
        kfunc_not_found();
        return 0;
    }
    va_list args;
    va_start(args, fmt);
    int rc = kfunc(seq_buf_printf)(s, fmt, args);
    va_end(args);
    return rc;
}
static inline int seq_buf_to_user(struct seq_buf *s, char __user *ubuf, int cnt)
{
    kfunc_call(seq_buf_to_user, s, ubuf, cnt);
    kfunc_not_found();
    return 0;
}
static inline int seq_buf_puts(struct seq_buf *s, const char *str)
{
    kfunc_call(seq_buf_puts, s, str);
    kfunc_not_found();
    return 0;
}
static inline int seq_buf_putc(struct seq_buf *s, unsigned char c)
{
    kfunc_call(seq_buf_putc, s, c);
    kfunc_not_found();
    return 0;
}
static inline int seq_buf_putmem(struct seq_buf *s, const void *mem, unsigned int len)
{
    kfunc_call(seq_buf_putmem, s, mem, len);
    kfunc_not_found();
    return 0;
}
static inline int seq_buf_putmem_hex(struct seq_buf *s, const void *mem, unsigned int len)
{
    kfunc_call(seq_buf_putmem_hex, s, mem, len);
    kfunc_not_found();
    return 0;
}
static inline int seq_buf_bitmask(struct seq_buf *s, const unsigned long *maskp, int nmaskbits)
{
    kfunc_call(seq_buf_bitmask, s, maskp, nmaskbits);
    kfunc_not_found();
    return 0;
}

static inline int seq_buf_copy_to_user(void __user *to, const void *from, int n)
{
    struct seq_buf seq_buf;
    seq_buf_clear(&seq_buf);
    seq_buf.buffer = (void *)from;
    seq_buf.len = n;
    return seq_buf_to_user(&seq_buf, to, n);
}

#endif