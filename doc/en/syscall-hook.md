# System Call Hook

KernelPatch provides specialized support for hooking system calls on arm64.

## Overview

System call hooking can be done in two ways in KernelPatch:
1. **Syscall Table Hooking**: Modifying the `sys_call_table`.
2. **Inline Hooking**: Hooking the syscall function itself (e.g., `__arm64_sys_openat`).

KernelPatch provides a unified API for both.

## API Reference

### `inline_hook_syscalln`

Hooks a system call by its number using an inline hook.

```c
hook_err_t inline_hook_syscalln(int nr, int32_t argno, void *before, void *after, void *udata);
```

### `fp_hook_syscalln`

Hooks a system call by its number by modifying the syscall table (if possible) or using other function pointer replacement techniques.

```c
hook_err_t fp_hook_syscalln(int nr, int32_t argno, void *before, void *after, void *udata);
```

### `syscall_argn`

Helper macro to retrieve syscall arguments from the `args` structure.

```c
uint64_t syscall_argn(void *args, int n);
```

## Example

The following example (adapted from `kpms/demo-syscallhook`) demonstrates how to hook the `openat` syscall.

```c
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

void before_openat(hook_fargs4_t *args, void *udata) {
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    
    char buf[1024];
    compat_strncpy_from_user(buf, filename, sizeof(buf));
    
    pr_info("openat called for: %s\n", buf);
}

// Installation:
inline_hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
```

## Considerations

- Hooking syscalls globally can have a significant performance impact.
- Be careful when accessing user-space memory; use `compat_copy_from_user` or `compat_strncpy_from_user` to safely copy data.
- System call numbers can vary between architectures, but KernelPatch focuses on arm64.
