/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>

KPM_NAME("kpm-import-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module cross-KPM symbol import example");

/* Resolved at load time against the exports of already-loaded KPMs
 * (kpm-exports-demo must be loaded first), exactly like an LKM importing
 * another module's EXPORT_SYMBOL. */
extern int kpm_exports_add(int a, int b);

static long import_init(const char *args, const char *event, void *__user reserved)
{
    int v = kpm_exports_add(20, 22);
    pr_info("kpm import init, event: %s\n", event);
    pr_info("imported kpm_exports_add(20, 22) = %d\n", v);
    return 0;
}

static long import_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm import control0, args: %s\n", args);
    return 0;
}

static long import_exit(void *__user reserved)
{
    pr_info("kpm import exit\n");
    return 0;
}

KPM_INIT(import_init);
KPM_CTL0(import_control0);
KPM_EXIT(import_exit);
