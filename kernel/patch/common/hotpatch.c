/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <hotpatch.h>

#include <linux/stop_machine.h>
#include <linux/init_task.h>
#include <linux/sched.h>
#include <linux/include/vdso/limits.h>
#include <linux/stacktrace.h>
#include <uapi/asm-generic/errno.h>

#define MAX_STACK_TRACE_DEPTH 64
// static unsigned long stack_entries[MAX_STACK_TRACE_DEPTH];
// static struct stack_trace trace = { 0 };

// static int backtrace_address_verify(unsigned long address, bool replace)
// {
//     return 0;
// }

/*
 * https://github.com/dynup/kpatch/blob/922cd458091915b0dad8c1892d7a609addd4afd7/kmod/core/core.c#L274C20-L274C20
 * Verify activeness safety, i.e. that none of the to-be-patched functions are on the stack of any task.
 */
int patch_verify_safety()
{
    // if (task_struct_offset.tasks_offset < 0) {
    //     return -1;
    // }
    int ret = 0;

    // trace.max_entries = sizeof(stack_entries) / sizeof(stack_entries[0]);
    // trace.entries = &stack_entries[0];

    // struct task_struct *g, *t;

    // do_each_thread(p)
    // {
    //         trace.nr_entries = 0;
    //         save_stack_trace_tsk(t, &trace);

    //         if (trace.nr_entries >= trace.max_entries) {
    //             logke("more than %u trace entries!\n", trace.max_entries);
    //             ret = -EBUSY;
    //             goto out;
    //         }

    //         for (int i = 0; i < trace.nr_entries; i++) {
    //             if (trace.entries[i] == ULONG_MAX)
    //                 break;
    //             ret = backtrace_address_verify(trace.entries[i], 0);
    //             if (ret)
    //                 goto out;
    //         }
    // }

    // out:
    //     if (ret) {
    //         // pid_t pid =
    //         logke("Comm: %.20s\n", get_task_comm(t));
    //         for (int i = 0; i < trace.nr_entries; i++) {
    //             if (trace.entries[i] == ULONG_MAX)
    //                 break;
    //             logke("  [<%pK>] %pB\n", (void *)trace.entries[i], (void *)trace.entries[i]);
    //         }
    //     }

    return ret;
}

// static int check_all_task(void *data)
// {
//     hook_t *hook = (hook_t *)data;
//     logkd("check_all_task data: %llx\n", hook);
//     return 0;
// }

int hot_patch_text()
{
    // int rc = stop_machine(check_all_task, &data, 0);
    // logkd("stop_machine rc: %d\n", rc);
    return 0;
}
