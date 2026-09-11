# Syscall Hook

KernelPatch provides dedicated APIs for hooking Linux system calls. These are built on top of the inline hook framework and handle the differences between kernels with and without syscall wrappers automatically.

## Overview

Two hooking strategies are available:

| Strategy | API prefix | Description |
|----------|-----------|-------------|
| Inline hook | `inline_hook_syscalln` | Patches the syscall handler function's code directly |
| Function pointer hook | `fp_hook_syscalln` | Replaces the function pointer in the syscall table |

Both strategies support multiple simultaneous hooks on the same syscall via a chain mechanism.

## Accessing Syscall Arguments

Because some kernels wrap syscalls with a `pt_regs` parameter, always use the provided helpers to access arguments instead of reading `fargs->argN` directly:

```c
#include <syscall.h>

// Read argument n (0-based)
uint64_t val = syscall_argn(args, n);

// Write argument n
set_syscall_argn(args, n, new_val);
```

## Inline Syscall Hook

```c
hook_err_t inline_hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
void inline_unhook_syscalln(int nr, void *before, void *after);
```

| Parameter | Description |
|-----------|-------------|
| `nr`      | Syscall number (e.g., `__NR_openat`) |
| `narg`    | Number of syscall arguments |
| `before`  | Callback called before the syscall handler |
| `after`   | Callback called after the syscall handler (can be `NULL`) |
| `udata`   | User data pointer passed to callbacks |

For 32-bit compat syscalls:

```c
hook_err_t inline_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata);
void inline_unhook_compat_syscalln(int nr, void *before, void *after);
```

## Function Pointer Syscall Hook

```c
hook_err_t fp_hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
void fp_unhook_syscalln(int nr, void *before, void *after);
```

For 32-bit compat syscalls:

```c
hook_err_t fp_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata);
void fp_unhook_compat_syscalln(int nr, void *before, void *after);
```

## Generic Hook (Auto-Select Strategy)

```c
hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
void unhook_syscalln(int nr, void *before, void *after);

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata);
void unhook_compat_syscalln(int nr, void *before, void *after);
```

These automatically select the best hooking method for the current kernel.

On kernels with syscall wrappers, `hook_syscalln` first tries to install a single
inline hook on `invoke_syscall`, the function every syscall (native and compat32)
goes through after `syscall_trace_enter` and before `syscall_trace_exit`.
Registrations are dispatched from that one hook, so the syscall table is never
modified and all syscalls share the same trampoline overhead with no per-syscall
timing fingerprint. If `invoke_syscall` is not a symbol (inlined, etc.) it falls
back to hooking `el0_svc_common`, then to the per-syscall `fp_hook_syscalln` /
`inline_hook_syscalln` mechanism.

`syscall_hook_global_enabled()` reports whether the global hook is active.
`hook_syscalln_override` is like `hook_syscalln` but its callback may set
`skip_origin`; it is honoured when the hook sits on `invoke_syscall` and falls
back to the per-syscall mechanism otherwise.

## Callback Signature

Syscall hook callbacks use the same `hook_fargs*_t` types as inline hooks. For a syscall with 4 arguments, use `hook_fargs4_t`:

```c
void before_openat(hook_fargs4_t *args, void *udata)
{
    // Access arguments using syscall_argn()
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);

    // Read string from userspace
    char buf[256];
    compat_strncpy_from_user(buf, filename, sizeof(buf));

    pr_info("openat: dfd=%d, path=%s, flags=%x\n", dfd, buf, flags);
}

void after_openat(hook_fargs4_t *args, void *udata)
{
    long retval = (long)args->ret;
    pr_info("openat returned: %ld\n", retval);
    // Override return value:
    // args->ret = -EPERM;
}
```

## Example: Hook openat with Two Independent Chains

```c
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <kputils.h>

KPM_NAME("kpm-syscall-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("author");
KPM_DESCRIPTION("Syscall hook example");

uint64_t open_counts = 0;

void before_openat_0(hook_fargs4_t *args, void *udata)
{
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[256];
    compat_strncpy_from_user(buf, filename, sizeof(buf));
    pr_info("chain0 before openat: %s\n", buf);
}

void before_openat_1(hook_fargs4_t *args, void *udata)
{
    uint64_t *pcount = (uint64_t *)udata;
    (*pcount)++;
    pr_info("chain1 before openat count: %llu\n", *pcount);
}

void after_openat_1(hook_fargs4_t *args, void *udata)
{
    pr_info("chain1 after openat ret: %ld\n", (long)args->ret);
}

static long my_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;

    err = fp_hook_syscalln(__NR_openat, 4, before_openat_0, NULL, NULL);
    if (err) { pr_err("hook chain0 failed: %d\n", err); return 0; }

    err = fp_hook_syscalln(__NR_openat, 4, before_openat_1, after_openat_1, &open_counts);
    if (err) { pr_err("hook chain1 failed: %d\n", err); }

    return 0;
}

static long my_exit(void *reserved)
{
    fp_unhook_syscalln(__NR_openat, before_openat_0, NULL);
    fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
    return 0;
}

KPM_INIT(my_init);
KPM_EXIT(my_exit);
```

## Skipping the Original Syscall

Set `args->skip_origin = 1` in the `before` callback to prevent the original syscall from executing. You should also set `args->ret` to an appropriate return value:

```c
void before_openat(hook_fargs4_t *args, void *udata)
{
    // Block all open calls
    args->skip_origin = 1;
    args->ret = (uint64_t)-EPERM;
}
```

> Register such a hook with `hook_syscalln_override`, not `hook_syscalln`. It is
> honoured only when the global dispatcher is hooked at `invoke_syscall` (handler
> granularity), where skipping origin suppresses just the real syscall while
> `el0_svc_common` still performs its entry/exit work. If the dispatcher could
> only hook `el0_svc_common`, or is not active, `hook_syscalln_override` falls
> back to the per-syscall mechanism, which also supports `skip_origin`.
> `hook_syscalln` itself never honours it.

## Notes

- `syscall_argn()` must be used instead of `args->argN` directly, because on kernels with `CONFIG_HAVE_SYSCALL_WRAPPERS`, the first argument to the handler is a `pt_regs *` pointer.
- Always call the unhook function in your KPM exit callback.
- Both inline and function-pointer strategies support chains of up to 16 simultaneous hooks per syscall.
- Use `compat_strncpy_from_user` / `compat_copy_to_user` for safe userspace memory access inside hooks.
