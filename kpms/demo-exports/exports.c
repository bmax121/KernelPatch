/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>

KPM_NAME("kpm-exports-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module cross-KPM symbol export example");

/* KPM_EXPORT publishes this function to later KPMs, the same way an LKM
 * publishes a symbol with EXPORT_SYMBOL. */
int kpm_exports_add(int a, int b)
{
    return a + b;
}
KPM_EXPORT(kpm_exports_add);

static long exports_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("kpm exports init, event: %s, args: %s\n", event, args);
    pr_info("kpm_exports_add(20, 22) = %d (importable by other KPMs)\n", kpm_exports_add(20, 22));
    return 0;
}

static long exports_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm exports control0, args: %s\n", args);
    return 0;
}

static long exports_exit(void *__user reserved)
{
    pr_info("kpm exports exit\n");
    return 0;
}

KPM_INIT(exports_init);
KPM_CTL0(exports_control0);
KPM_EXIT(exports_exit);
