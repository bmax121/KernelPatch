# Kernel Inline Hook

KernelPatch provides a powerful inline hooking mechanism for the Linux kernel on arm64. It allows you to intercept function calls, inspect or modify arguments, and change return values.

## Overview

Inline hooking in KernelPatch is primarily done through the `hook_wrap` family of functions. These functions allow you to "wrap" a target function with `before` and `after` callbacks.

The main advantages of `hook_wrap` over a raw `hook` are:
- Multiple modules can hook the same function safely.
- You don't need to manually manage the original function call (it's handled by the framework).
- Easy access to arguments and return values.

## API Reference

### `hook_wrap{n}`

Wraps a function with `n` arguments. `n` can be from 0 to 12.

```c
hook_err_t hook_wrap{n}(void *func, hook_chain{n}_callback before, hook_chain{n}_callback after, void *udata);
```

- `func`: The address of the function to hook.
- `before`: Callback called before the original function.
- `after`: Callback called after the original function.
- `udata`: User-defined data passed to both callbacks.

### `hook_unwrap`

Removes a hook previously installed with `hook_wrap`.

```c
void hook_unwrap(void *func, void *before, void *after);
```

## Example

The following example (from `kpms/demo-inlinehook`) demonstrates how to hook a simple `add` function.

```c
#include <hook.h>
#include <linux/printk.h>

// Function to be hooked
int __noinline add(int a, int b) {
    return a + b;
}

// Before callback
void before_add(hook_fargs2_t *args, void *udata) {
    pr_info("before add: %d, %d\n", (int)args->arg0, (int)args->arg1);
}

// After callback
void after_add(hook_fargs2_t *args, void *udata) {
    pr_info("after add ret: %d\n", (int)args->ret);
    args->ret = 100; // Modify return value
}

// Installation:
hook_wrap2((void *)add, before_add, after_add, NULL);
```

## How it Works

1. **Instruction Replacement**: KernelPatch replaces the first few instructions of the target function with a branch to a trampoline.
2. **Trampoline**: The trampoline saves the CPU state and calls the `before` callbacks in the hook chain.
3. **Original Function**: The trampoline then executes the original (displaced) instructions and branches back to the target function (after the hook point).
4. **After Hook**: When the original function returns, it returns to another trampoline that calls the `after` callbacks and then returns to the original caller.

## Limitations

- Currently only supports **arm64**.
- Functions must be long enough to be hooked (at least 4 bytes for a branch, but typically more for safety).
- Functions marked as `notrace` or in certain critical sections might be dangerous to hook.
