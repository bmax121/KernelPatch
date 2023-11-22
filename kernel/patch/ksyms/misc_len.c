#ifndef _KP_MISC_LEN_H_
#define _KP_MISC_LEN_H_

#include <ktypes.h>
#include <ksyms.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/sched/task.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include <linux/init_task.h>

struct task_struct *kvar(init_task) = 0;
union thread_union *kvar(init_thread_union) = 0;
struct cred *kvar(init_cred) = 0;
struct group_info *kvar(init_groups) = 0;

int kvlen(init_task) = -1;
int kvlen(init_cred) = -1;
int kvlen(init_thread_union) = -1;

int linux_sybmol_len_init()
{
    int rc = 0;

    kvar_match(init_task, name, addr);
    kvar_match(init_thread_union, name, addr);
    kvar_match(init_cred, name, addr);
    kvar_match(init_groups, name, addr);

    if (!kvar(init_task) || !kvar(init_thread_union) || !kvar(init_cred) || !kvar(init_groups)) {
        rc = -ENOENT;
        log_boot("no symbol init_task or init_thread_union or init_cred or init_groups\n");
        goto out;
    }

    unsigned long offset = 0;
    unsigned long size = 0;
    char mod[16] = { '\0' };
    char name[16] = { '\0' };

    log_boot("struct size: \n");

    lookup_symbol_attrs((unsigned long)kvar(init_cred), &size, &offset, mod, name);
    kvlen(init_cred) = size;
    log_boot("    init_cred: %x\n", size);

    lookup_symbol_attrs((unsigned long)kvar(init_task), &size, &offset, mod, name);
    kvlen(init_task) = size;
    log_boot("    init_task: %x\n", size);

    lookup_symbol_attrs((unsigned long)kvar(init_thread_union), &size, &offset, mod, name);
    kvlen(init_thread_union) = size;
    thread_size = size;
    log_boot("    thread_union: %x\n", size);

out:
    return rc;
}

#endif