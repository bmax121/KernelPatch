#include <kputils.h>
#include <linux/seq_buf.h>
#include <linux/trace_seq.h>
#include <pgtable.h>
#include <linux/string.h>

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
    if (n > page_size) {
        return 0;
    }
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

int __must_check seq_copy_to_user(void __user *to, const void *from, int n)
{
    int copy_len;
    if (kfunc(seq_buf_to_user)) {
        copy_len = seq_buf_copy_to_user((void *__user)to, from, n);
    } else {
        copy_len = trace_seq_copy_to_user((void *__user)to, from, n);
    }
    return copy_len;
}