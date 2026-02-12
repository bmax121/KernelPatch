# KernelPatch Module (KPM)

KernelPatch Modules (KPM) are loadable components that can extend the kernel's functionality or apply patches at runtime. They are similar to standard Linux Kernel Modules (LKM) but are designed to work within the KernelPatch framework.

## Lifecycle

A KPM defines several lifecycle callbacks:

- `KPM_INIT(fn)`: Called when the module is loaded.
- `KPM_EXIT(fn)`: Called when the module is unloaded.
- `KPM_CTL0(fn)`: Control interface 0 (typically for small arguments/messages).
- `KPM_CTL1(fn)`: Control interface 1 (typically for more complex arguments).

## Module Metadata

Each KPM should define the following metadata:

- `KPM_NAME("name")`: Unique name of the module.
- `KPM_VERSION("version")`: Version string.
- `KPM_LICENSE("license")`: License (e.g., "GPL v2").
- `KPM_AUTHOR("author")`: Author name.
- `KPM_DESCRIPTION("description")`: Brief description of what the module does.

## Example Structure

```c
#include <kpmodule.h>
#include <linux/printk.h>

KPM_NAME("my-module");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");

static long my_init(const char *args, const char *event, void *reserved) {
    pr_info("Module loaded\n");
    return 0;
}

static long my_exit(void *reserved) {
    pr_info("Module unloaded\n");
    return 0;
}

KPM_INIT(my_init);
KPM_EXIT(my_exit);
```

## Compilation

KPMs are typically compiled using a cross-compiler targeting arm64. The `Makefile` in the demo directories provides a template for compilation.

```bash
make TARGET_COMPILE=aarch64-linux-gnu- KP_DIR=/path/to/KernelPatch
```
