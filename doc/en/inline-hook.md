# Kernel Inline Hook

KernelPatch provides a powerful inline hook framework for ARM64. It allows you to intercept and modify the behavior of arbitrary kernel functions at runtime.

## Overview

There are two hooking approaches available:

- **`hook` / `unhook`**: Simple single-replacement hook. Only one hook per function; conflicts occur if multiple modules hook the same function simultaneously.
- **`hook_wrap` / `hook_unwrap`**: Chain-based hook supporting multiple independent hooks on the same function. Recommended for use in KPMs.

## hook_wrap (Recommended)

`hook_wrap` installs a **before** callback (called before the original function) and/or an **after** callback (called after the original function). Multiple callers can independently hook the same function using a chain.

### Signature

```c
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata);
```

| Parameter | Description |
|-----------|-------------|
| `func`    | Address of the target kernel function |
| `argno`   | Number of arguments the target function takes (0–12) |
| `before`  | Callback invoked before the original function (can be `NULL`) |
| `after`   | Callback invoked after the original function (can be `NULL`) |
| `udata`   | User data pointer passed to the callbacks |

Typed convenience wrappers are provided: `hook_wrap0` through `hook_wrap12`.

### Callback Signature

The callback type depends on the number of arguments (`argno`):

```c
// For argno = 2
typedef void (*hook_chain2_callback)(hook_fargs2_t *fargs, void *udata);
```

The `fargs` structure provides access to function arguments and the return value:

```c
typedef struct {
    void *chain;        // Internal chain pointer
    int skip_origin;    // Set to non-zero to skip calling the original function
    hook_local_t local; // 8 x uint64_t slots for sharing data between before/after
    uint64_t ret;       // Return value (read/write in after callback)
    uint64_t arg0;      // Function arguments
    uint64_t arg1;
    // ...
} hook_fargs2_t;
```

### Hook Local Data

`fargs->local` contains 8 x `uint64_t` slots (`data0`–`data7`) shared between the `before` and `after` callbacks of the same chain item. This is useful for passing context from `before` to `after`:

```c
void before_fn(hook_fargs2_t *args, void *udata) {
    args->local.data0 = args->arg0; // Save arg0 for use in after
}

void after_fn(hook_fargs2_t *args, void *udata) {
    uint64_t saved = args->local.data0;
}
```

### Unhooking

```c
void hook_unwrap(void *func, void *before, void *after);
```

Pass the same `before` and `after` pointers used during `hook_wrap`.

### Multiple Hooks on the Same Function (Chain)

Multiple independent callers can hook the same function simultaneously. Each `hook_wrap` call registers its own `before`/`after` pair as a **chain item**. With N registered items, the call sequence on every invocation is:

```text
before[0] → before[1] → ... → before[N-1]
    → original function  (skipped if any before sets skip_origin = 1)
        → after[N-1] → ... → after[1] → after[0]
```

- `before` callbacks run in **insertion order**; `after` callbacks run in **reverse** order.
- The `fargs` object is **shared** across all callbacks — a `before` can modify arguments that later callbacks will see; an `after` can override the return value left by an earlier `after`.
- The chain is created automatically on the first `hook_wrap` and destroyed when the last item is removed via `hook_unwrap`.
- Registering the same callback pointer a second time returns `HOOK_DUPLICATED`.
- **No priority control**: items execute in insertion order with no cross-module ordering guarantee.
- **Shared `fargs->local`**: all chain items share the same `local` slots. Use `udata` for per-item private state instead.
- **Maximum 16 items** per function. Exceeding this returns `HOOK_CHAIN_FULL`.

## Example: Hooking a 2-Argument Function

```c
#include <hook.h>
#include <kpmodule.h>
#include <linux/printk.h>

KPM_NAME("my-hook-module");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("author");
KPM_DESCRIPTION("Inline hook example");

void before_add(hook_fargs2_t *args, void *udata)
{
    pr_info("before add: arg0=%d, arg1=%d\n", (int)args->arg0, (int)args->arg1);
    // Optionally modify arguments:
    // args->arg0 = 42;
    // Optionally skip the original function:
    // args->skip_origin = 1;
    // args->ret = 0;
}

void after_add(hook_fargs2_t *args, void *udata)
{
    pr_info("after add: ret=%d\n", (int)args->ret);
    // Optionally override return value:
    // args->ret = 100;
}

static long my_init(const char *args, const char *event, void *reserved)
{
    void *target_func = (void *)kallsyms_lookup_name("target_function_name");
    hook_err_t err = hook_wrap2(target_func, before_add, after_add, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("hook failed: %d\n", err);
    }
    return 0;
}

static long my_exit(void *reserved)
{
    void *target_func = (void *)kallsyms_lookup_name("target_function_name");
    hook_unwrap(target_func, before_add, after_add);
    return 0;
}

KPM_INIT(my_init);
KPM_EXIT(my_exit);
```

## Simple hook / unhook

If you only need a single replacement and won't have multiple modules hooking the same function:

```c
hook_err_t hook(void *func, void *replace, void **backup);
void unhook(void *func);
```

`backup` receives a pointer to the original function, which you can call from your replacement to invoke the original behavior.

> **Warning:** If multiple KPMs use `hook()` on the same function simultaneously, they will conflict. Prefer `hook_wrap` for module code.

## Function Pointer Hook

For functions accessed through a function pointer (e.g., in a vtable or ops struct), use `fp_hook_wrap`:

```c
hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata);
void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after);
```

`fp_addr` is the address of the function pointer variable, not the function itself.

Typed convenience wrappers: `fp_hook_wrap0` through `fp_hook_wrap12`.

To get the original function pointer inside a callback:

```c
void *orig = fp_get_origin_func(args);
```

## Error Codes

| Code | Value | Meaning |
|------|-------|---------|
| `HOOK_NO_ERR` | 0 | Success |
| `HOOK_BAD_ADDRESS` | 4095 | Invalid function address |
| `HOOK_DUPLICATED` | 4094 | Hook already installed |
| `HOOK_NO_MEM` | 4093 | Out of memory |
| `HOOK_BAD_RELO` | 4092 | Instruction relocation failed |
| `HOOK_TRANSIT_NO_MEM` | 4091 | Transit buffer out of memory |
| `HOOK_CHAIN_FULL` | 4090 | Hook chain is full (max 16 items) |

## Notes

- The hook framework is ARM64-only.
- Up to 16 chain items (`HOOK_CHAIN_NUM`) per function when using `hook_wrap`.
- Function pointer hook chains support up to 32 items (`FP_HOOK_CHAIN_NUM`).
- The kernel function must be findable via `kallsyms_lookup_name` or by other means.
- Always unhook in your KPM's exit callback to avoid dangling hooks.

## TODO

- **Hook chain priority**: Support specifying a priority when adding a chain item via `hook_wrap`, so that higher-priority callbacks are guaranteed to run before lower-priority ones. Currently chain items execute in insertion order with no way to control relative ordering across modules.

- **Hook local data isolation**: Currently `fargs->local` is a single `hook_local_t` shared across all chain items for the same function call. Each `before`/`after` pair should have its own independent `local` storage so that data written by one chain item cannot collide with or be overwritten by another chain item's local data.
