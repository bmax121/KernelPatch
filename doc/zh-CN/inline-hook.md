# 内核 Inline Hook

KernelPatch 为 ARM64 提供了强大的 inline hook 框架，可在运行时拦截并修改任意内核函数的行为。

## 概述

提供两种 hook 方式：

- **`hook` / `unhook`**：简单的单一替换 hook。每个函数只能有一个 hook；多个模块同时 hook 同一函数会产生冲突。
- **`hook_wrap` / `hook_unwrap`**：基于链的 hook，支持多个模块独立 hook 同一函数。KPM 开发推荐使用此方式。

## hook_wrap（推荐）

`hook_wrap` 注册一个 **before** 回调（在原函数执行前调用）和/或一个 **after** 回调（在原函数执行后调用）。多个调用方可以通过链机制独立 hook 同一函数。

### 函数签名

```c
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata);
```

| 参数 | 说明 |
|------|------|
| `func` | 目标内核函数的地址 |
| `argno` | 目标函数的参数个数（0–12） |
| `before` | 在原函数执行前调用的回调（可为 `NULL`） |
| `after` | 在原函数执行后调用的回调（可为 `NULL`） |
| `udata` | 传递给回调的用户数据指针 |

`<hook.h>` 中提供了类型化的便捷封装：`hook_wrap0` 到 `hook_wrap12`。

### 回调签名

回调类型取决于参数个数（`argno`）：

```c
// argno = 2 时
typedef void (*hook_chain2_callback)(hook_fargs2_t *fargs, void *udata);
```

`fargs` 结构体提供对函数参数和返回值的访问：

```c
typedef struct {
    void *chain;        // 内部链指针
    int skip_origin;    // 设为非零值则跳过原函数调用
    hook_local_t local; // 8 个 uint64_t 槽，用于 before/after 之间传递数据
    uint64_t ret;       // 返回值（在 after 回调中读写）
    uint64_t arg0;      // 函数参数
    uint64_t arg1;
    // ...
} hook_fargs2_t;
```

### Hook 本地数据

`fargs->local` 包含 8 个 `uint64_t` 槽（`data0`–`data7`），在同一链项的 `before` 和 `after` 回调之间共享，可用于从 `before` 向 `after` 传递上下文：

```c
void before_fn(hook_fargs2_t *args, void *udata) {
    args->local.data0 = args->arg0; // 保存 arg0 供 after 使用
}

void after_fn(hook_fargs2_t *args, void *udata) {
    uint64_t saved = args->local.data0;
}
```

### 解除 Hook

```c
void hook_unwrap(void *func, void *before, void *after);
```

传入与 `hook_wrap` 时相同的 `before` 和 `after` 指针。

### 同一函数的多个 Hook（链）

多个独立调用方可以同时 hook 同一函数。每次 `hook_wrap` 调用将自己的 `before`/`after` 对注册为一个**链项**。有 N 个链项时，每次调用被 hook 函数的执行序列为：

```text
before[0] → before[1] → ... → before[N-1]
    → 原函数（若任意 before 设置了 skip_origin = 1 则跳过）
        → after[N-1] → ... → after[1] → after[0]
```

- `before` 回调按**插入顺序**执行；`after` 回调按**逆序**执行。
- `fargs` 对象在所有回调间**共享**——`before` 修改的参数对后续回调和原函数可见；`after` 可以覆盖更早的 `after` 设置的返回值。
- 链在第一次 `hook_wrap` 时自动创建，在最后一个 `hook_unwrap` 时自动销毁。
- 重复注册同一回调指针会返回 `HOOK_DUPLICATED`。
- **无优先级控制**：链项按插入顺序执行，无法保证跨模块的顺序。
- **`fargs->local` 共享**：所有链项共享同一组 `local` 槽。如需每个链项独立的私有状态，请使用 `udata`。
- 每个函数最多 **16 个链项**，超出则返回 `HOOK_CHAIN_FULL`。

## 示例：Hook 一个 2 参数函数

```c
#include <hook.h>
#include <kpmodule.h>
#include <linux/printk.h>

KPM_NAME("my-hook-module");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("author");
KPM_DESCRIPTION("Inline hook 示例");

void before_add(hook_fargs2_t *args, void *udata)
{
    pr_info("before add: arg0=%d, arg1=%d\n", (int)args->arg0, (int)args->arg1);
    // 可选：修改参数
    // args->arg0 = 42;
    // 可选：跳过原函数
    // args->skip_origin = 1;
    // args->ret = 0;
}

void after_add(hook_fargs2_t *args, void *udata)
{
    pr_info("after add: ret=%d\n", (int)args->ret);
    // 可选：覆盖返回值
    // args->ret = 100;
}

static long my_init(const char *args, const char *event, void *reserved)
{
    void *target_func = (void *)kallsyms_lookup_name("target_function_name");
    hook_err_t err = hook_wrap2(target_func, before_add, after_add, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("hook 失败: %d\n", err);
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

## 简单 hook / unhook

如果只需要单一替换且不会有多个模块同时 hook 同一函数：

```c
hook_err_t hook(void *func, void *replace, void **backup);
void unhook(void *func);
```

`backup` 接收原函数的指针，可从替换函数中调用它来执行原始行为。

> **警告：** 多个 KPM 同时对同一函数使用 `hook()` 会产生冲突。模块代码请优先使用 `hook_wrap`。

## 函数指针 Hook

对于通过函数指针访问的函数（如 vtable 或 ops 结构体中的函数指针），使用 `fp_hook_wrap`：

```c
hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata);
void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after);
```

`fp_addr` 是函数指针变量的地址，而非函数本身的地址。

类型化便捷封装：`fp_hook_wrap0` 到 `fp_hook_wrap12`。

在回调中获取原始函数指针：

```c
void *orig = fp_get_origin_func(args);
```

## 错误码

| 错误码 | 值 | 说明 |
|--------|-----|------|
| `HOOK_NO_ERR` | 0 | 成功 |
| `HOOK_BAD_ADDRESS` | 4095 | 无效的函数地址 |
| `HOOK_DUPLICATED` | 4094 | Hook 已安装（重复注册） |
| `HOOK_NO_MEM` | 4093 | 内存不足 |
| `HOOK_BAD_RELO` | 4092 | 指令重定位失败 |
| `HOOK_TRANSIT_NO_MEM` | 4091 | Transit 缓冲区内存不足 |
| `HOOK_CHAIN_FULL` | 4090 | Hook 链已满（最多 16 个） |

## 注意事项

- Hook 框架仅支持 ARM64。
- 使用 `hook_wrap` 时，每个函数最多支持 16 个链项（`HOOK_CHAIN_NUM`）。
- 函数指针 Hook 链最多支持 32 个链项（`FP_HOOK_CHAIN_NUM`）。
- 目标内核函数需可通过 `kallsyms_lookup_name` 或其他方式获取地址。
- 务必在 KPM 的 exit 回调中解除 hook，避免悬空 hook。

## TODO

- **Hook 链优先级**：支持在 `hook_wrap` 添加链项时指定优先级，保证高优先级回调先于低优先级回调执行。目前链项按插入顺序执行，无法控制跨模块的相对顺序。

- **Hook local data 隔离**：目前 `fargs->local` 是同一函数调用中所有链项共享的单个 `hook_local_t`，应改为每个 `before`/`after` 对拥有独立的 local 存储，避免不同链项的数据相互覆盖。
