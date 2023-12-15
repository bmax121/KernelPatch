#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>

KPM_NAME("kpm-hello-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module Example");

int hello_init(const char *args)
{
    pr_info("kpm hello init, args: %s\n", args);
    pr_info("KernelPatch Version: %x\n", kpver);
    return 0;
}

void hello_exit()
{
    pr_info("kpm hello exit\n");
}

KPM_INIT(hello_init);
KPM_EXIT(hello_exit);
