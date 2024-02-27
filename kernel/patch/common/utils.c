/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <kputils.h>
#include <linux/seq_buf.h>
#include <linux/trace_seq.h>
#include <pgtable.h>
#include <linux/string.h>
#include <symbol.h>
#include <asm/processor.h>
#include <predata.h>
#include <linux/ptrace.h>
#include <linux/err.h>

int trace_seq_copy_to_user(void __user *to, const void *from, int n)
{
    unsigned char trace_seq_data[page_size + 0x20];
    struct trace_seq *trace_seq = (struct trace_seq *)trace_seq_data;
    int *fp = (int *)(((uintptr_t)trace_seq) + page_size);
    int *plen = fp;
    int *preadpos = fp + 1;
    int *pfull = fp + 2;
    unsigned char *pbuffer = (unsigned char *)trace_seq;
    *plen = n;
    *preadpos = 0;
    *pfull = 0;
    if (n > page_size) return 0;
    memcpy(pbuffer, from, n);
    int sz = trace_seq_to_user(trace_seq, to, n);
    return sz;
}

int seq_buf_copy_to_user(void __user *to, const void *from, int n)
{
    struct seq_buf seq_buf;
    seq_buf.size = n;
    seq_buf.len = n;
    seq_buf.readpos = 0;
    seq_buf.buffer = (void *)from;
    return seq_buf_to_user(&seq_buf, to, n);
}

int __must_check compat_copy_to_user(void __user *to, const void *from, int n)
{
    int copy_len;
    if (kfunc(seq_buf_to_user)) {
        copy_len = seq_buf_copy_to_user((void *__user)to, from, n);
    } else {
        copy_len = trace_seq_copy_to_user((void *__user)to, from, n);
    }
    return copy_len;
}
KP_EXPORT_SYMBOL(compat_copy_to_user);

#include <linux/uaccess.h>

long compact_strncpy_from_user(char *dest, const char __user *src, long count)
{
    if (kfunc(strncpy_from_user)) {
        long rc = kfunc(strncpy_from_user)(dest, src, count);
        if (rc >= count) {
            rc = count;
            dest[rc - 1] = '\0';
        } else if (rc > 0) {
            rc++;
        }
        return rc;
    }
    kfunc_call(compact_strncpy_from_user, dest, src, count);
    kfunc_call(strncpy_from_unsafe_user, dest, src, count);
    return 0;
}
KP_EXPORT_SYMBOL(compact_strncpy_from_user);

int16_t pt_regs_offset = -1;

struct pt_regs *_task_pt_reg(struct task_struct *task)
{
    unsigned long stack = (unsigned long)task_stack_page(task);
    uintptr_t addr = (uintptr_t)(thread_size + stack);
    if (likely(pt_regs_offset > 0)) {
        addr -= pt_regs_offset;
    } else {
#ifndef ANDROID
        if (kver < VERSION(4, 4, 19)) {
            addr -= sizeof(struct pt_regs_lt4419);
        } else
#endif
            if (kver < VERSION(4, 14, 0)) {
            addr -= sizeof(struct pt_regs_lt4140);
        } else if (kver < VERSION(5, 10, 0)) {
            addr -= sizeof(struct pt_regs_lt5100);
        } else {
            addr -= sizeof(struct pt_regs);
        }
    }

    return (struct pt_regs *)(addr);
}
KP_EXPORT_SYMBOL(_task_pt_reg);

void *__user __must_check copy_to_user_stack(const void *data, int len)
{
    uintptr_t addr = current_user_stack_pointer();
    addr -= len;
    addr &= 0xFFFFFFFFFFFFFFF8;
    int cplen = compat_copy_to_user((void *)addr, data, len);
    return cplen > 0 ? (void *__user)addr : (void *)(long)cplen;
}
KP_EXPORT_SYMBOL(copy_to_user_stack);