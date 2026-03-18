# Syscall Hook

KernelPatch 提供专用的系统调用 hook API，底层基于 inline hook 框架，自动处理有无 syscall wrapper 的内核差异。

## 概述

提供两种 hook 策略：

| 策略 | API 前缀 | 说明 |
|------|---------|------|
| Inline hook | `inline_hook_syscalln` | 直接修补 syscall 处理函数的代码 |
| 函数指针 hook | `fp_hook_syscalln` | 替换 syscall 表中的函数指针 |

两种策略均通过链机制支持对同一 syscall 的多个并发 hook。

## 访问 Syscall 参数

由于部分内核的 syscall 处理函数使用 `pt_regs` 作为参数，必须使用以下辅助函数访问参数，不要直接读取 `fargs->argN`：

```c
#include <syscall.h>

// 读取第 n 个参数（从 0 开始）
uint64_t val = syscall_argn(args, n);

// 写入第 n 个参数
set_syscall_argn(args, n, new_val);
```

## Inline Syscall Hook

```c
hook_err_t inline_hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
void inline_unhook_syscalln(int nr, void *before, void *after);
```

| 参数 | 说明 |
|------|------|
| `nr` | syscall 号（如 `__NR_openat`） |
| `narg` | syscall 参数个数 |
| `before` | 在 syscall 处理函数执行前调用的回调 |
| `after` | 在 syscall 处理函数执行后调用的回调（可为 `NULL`） |
| `udata` | 传递给回调的用户数据指针 |

32 位兼容 syscall：

```c
hook_err_t inline_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata);
void inline_unhook_compat_syscalln(int nr, void *before, void *after);
```

## 函数指针 Syscall Hook

```c
hook_err_t fp_hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
void fp_unhook_syscalln(int nr, void *before, void *after);
```

32 位兼容 syscall：

```c
hook_err_t fp_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata);
void fp_unhook_compat_syscalln(int nr, void *before, void *after);
```

## 通用 Hook（自动选择策略）

```c
hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
void unhook_syscalln(int nr, void *before, void *after);

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata);
void unhook_compat_syscalln(int nr, void *before, void *after);
```

自动为当前内核选择最合适的 hook 方式。

## 回调签名

Syscall hook 回调使用与 inline hook 相同的 `hook_fargs*_t` 类型。对于有 4 个参数的 syscall，使用 `hook_fargs4_t`：

```c
void before_openat(hook_fargs4_t *args, void *udata)
{
    // 使用 syscall_argn() 访问参数
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);

    // 从用户空间读取字符串
    char buf[256];
    compat_strncpy_from_user(buf, filename, sizeof(buf));

    pr_info("openat: dfd=%d, path=%s, flags=%x\n", dfd, buf, flags);
}

void after_openat(hook_fargs4_t *args, void *udata)
{
    long retval = (long)args->ret;
    pr_info("openat 返回: %ld\n", retval);
    // 覆盖返回值：
    // args->ret = -EPERM;
}
```

## 示例：用两个独立链 Hook openat

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
KPM_DESCRIPTION("Syscall hook 示例");

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
    if (err) { pr_err("hook chain0 失败: %d\n", err); return 0; }

    err = fp_hook_syscalln(__NR_openat, 4, before_openat_1, after_openat_1, &open_counts);
    if (err) { pr_err("hook chain1 失败: %d\n", err); }

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

## 跳过原始 Syscall

在 `before` 回调中设置 `args->skip_origin = 1` 可阻止原始 syscall 执行，同时应将 `args->ret` 设为合适的返回值：

```c
void before_openat(hook_fargs4_t *args, void *udata)
{
    // 拦截所有 open 调用
    args->skip_origin = 1;
    args->ret = (uint64_t)-EPERM;
}
```

## 注意事项

- 必须使用 `syscall_argn()` 访问参数，不能直接使用 `args->argN`，因为在带 `CONFIG_HAVE_SYSCALL_WRAPPERS` 的内核中，处理函数的第一个参数是 `pt_regs *` 指针。
- 务必在 KPM 的 exit 回调中调用 unhook 函数。
- inline 和函数指针两种策略均支持每个 syscall 最多 16 个并发 hook 链项。
- 在 hook 内部访问用户空间内存时使用 `compat_strncpy_from_user` / `compat_copy_to_user`。
