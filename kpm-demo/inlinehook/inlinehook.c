#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>

KPM_NAME("kpm-inline-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module Inline Hook Example");

int __noinline add(int a, int b)
{
    logkd("origin add called\n");
    int ret = a + b;
    return ret;
}

void before_add(hook_fargs2_t *args, void *udata)
{
    logkd("before add arg0: %d, arg1: %d\n", (int)args->arg0, (int)args->arg1);
}

void after_add(hook_fargs2_t *args, void *udata)
{
    logkd("after add arg0: %d, arg1: %d, ret: %d\n", (int)args->arg0, (int)args->arg1, (int)args->ret);
    args->ret = 100;
}

int inline_hook_demo_init()
{
    logkd("kpm inline-hook-demo init\n");

    int a = 20;
    int b = 10;

    int ret = add(a, b);
    logkd("%d + %d = %d\n", a, b, ret);

    hook_err_t err = hook_wrap2((void *)add, before_add, after_add, 0);
    logkd("hook err: %d\n", err);

    ret = add(a, b);
    logkd("%d + %d = %d\n", a, b, ret);

    return 0;
}

void inline_hook_demo_exit()
{
    unhook((void *)add);

    int a = 20;
    int b = 10;

    int ret = add(a, b);
    logkd("%d + %d = %d\n", a, b, ret);

    logkd("kpm inline-hook-demo  exit\n");
}

KPM_INIT(inline_hook_demo_init);
KPM_EXIT(inline_hook_demo_exit);