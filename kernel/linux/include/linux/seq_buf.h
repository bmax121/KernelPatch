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

#endif