/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kbtf.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("kpm-btf-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("Kernel BTF struct/offset query demo");

// Resolve a member by hand using the low-level primitives, descending into
// anonymous struct/union members with the caller's own cycle set. This has no
// fixed depth cap, unlike the convenience helper kp_btf_member_offset.
static long btf_walk_offset(int type_id, const char *member, long byte, const int *seen, int nseen)
{
    const char *name;
    int kind;
    int vlen = kp_btf_type_info(type_id, &name, &kind, 0);
    if (vlen < 0 || (kind != 4 /*struct*/ && kind != 5 /*union*/)) return -1;

    for (int i = 0; i < nseen; i++)
        if (seen[i] == type_id) return -1; // cycle

    int seen2[64];
    if (nseen >= 64) return -1;
    for (int i = 0; i < nseen; i++) seen2[i] = seen[i];
    seen2[nseen] = type_id;

    for (int i = 0; i < vlen; i++) {
        const char *mname;
        int mtype;
        long bitoff;
        if (kp_btf_member(type_id, i, &mname, &mtype, &bitoff)) continue;
        if (mname && mname[0] && !strcmp(mname, member)) return byte + (bitoff >> 3);
        if (!mname || !mname[0]) { // anonymous -> recurse
            long r = btf_walk_offset(kp_btf_skip_mod(mtype), member, byte + (bitoff >> 3), seen2, nseen + 1);
            if (r >= 0) return r;
        }
    }
    return -1;
}

static long btf_demo_init(const char *args, const char *event, void *__user reserved)
{
    (void)reserved;

    pr_info("btf demo init, event: %s, args: %s\n", event, args);

    if (!kp_btf_available()) {
        pr_info("kernel BTF is not available\n");
        return 0;
    }

    // convenience helper (bounded depth)
    pr_info("sizeof(struct task_struct): %ld\n", kp_btf_type_size("task_struct"));
    pr_info("task_struct->cred offset: %ld\n", kp_btf_member_offset("task_struct", "cred"));
    pr_info("cred->uid offset: %ld\n", kp_btf_member_offset("cred", "uid"));
    pr_info("mm_struct->pgd offset: %ld\n", kp_btf_member_offset("mm_struct", "pgd"));

    // low-level primitives (manual walk, no depth cap)
    int mm = kp_btf_find_type("mm_struct");
    pr_info("mm_struct type id: %d, pgd offset (manual walk): %ld\n", mm, btf_walk_offset(mm, "pgd", 0, 0, 0));

    return 0;
}

static long btf_demo_exit(void *__user reserved)
{
    (void)reserved;
    pr_info("btf demo exit\n");
    return 0;
}

KPM_INIT(btf_demo_init);
KPM_EXIT(btf_demo_exit);
