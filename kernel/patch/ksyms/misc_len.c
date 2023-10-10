#ifndef _KP_MISC_LEN_H_
#define _KP_MISC_LEN_H_

#include <ktypes.h>
#include <ksyms.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/sched/task.h>
#include <asm/current.h>
#include <linux/init_task.h>

int kvlen(init_task) = -1;
int kvlen(init_cred) = -1;
int kvlen(init_thread_union) = -1;

void linux_sybmol_len_init()
{
    unsigned long offset = 0;
    unsigned long size = 0;
    char mod[16] = { '\0' };
    char name[16] = { '\0' };

    logkd("struct size:\n");

    lookup_symbol_attrs((unsigned long)kvar(init_cred), &size, &offset, mod, name);
    kvlen(init_cred) = size;
    logkd("    init_cred: %d\n", size);

    lookup_symbol_attrs((unsigned long)kvar(init_task), &size, &offset, mod, name);
    kvlen(init_task) = size;
    logkd("    init_task: %d\n", size);

    lookup_symbol_attrs((unsigned long)kvar(init_thread_union), &size, &offset, mod, name);
    kvlen(init_thread_union) = size;
    thread_size = size;
    logkd("    thread_size: %d\n", size);
}

#endif