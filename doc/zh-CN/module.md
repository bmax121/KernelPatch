# KernelPatch 模块（KPM）

KernelPatch 模块（KPM）是一种可由 KernelPatch 加载并在内核空间中运行的 ELF 文件。KPM 允许在不需要内核源码或构建系统的情况下，动态扩展或修改内核行为。

## 模块元信息

每个 KPM 必须使用以下宏（定义于 `<kpmodule.h>`）声明元信息：

```c
KPM_NAME("my-module");           // 唯一模块名称（最长 32 字节）
KPM_VERSION("1.0.0");            // 版本字符串（最长 32 字节）
KPM_LICENSE("GPL v2");           // 许可证（最长 32 字节）
KPM_AUTHOR("author");            // 作者名（最长 32 字节）
KPM_DESCRIPTION("description");  // 描述（最长 512 字节）
```

`KPM_NAME` 在所有已加载模块中必须唯一，它被用作控制和卸载操作的标识符。

## 生命周期回调

KPM 通过注册回调函数实现初始化、控制和清理：

### 初始化（Init）

```c
// 签名
typedef long (*mod_initcall_t)(const char *args, const char *event, void *reserved);

KPM_INIT(my_init_function);
```

模块加载时调用。参数说明：

- `args`：通过 `sc_kpm_load()` 传入的参数字符串。
- `event`：触发事件名称（如 `"load"`，或启动时由内核事件触发的字符串）。
- `reserved`：保留参数，始终为 `NULL`。

返回 `0` 表示成功，非零值表示初始化失败。

### 控制（ctl0）

```c
// 签名
typedef long (*mod_ctl0call_t)(const char *ctl_args, char *__user out_msg, int outlen);

KPM_CTL0(my_control0_function);
```

用户空间调用 `sc_kpm_control()` 时触发。参数说明：

- `ctl_args`：控制参数字符串。
- `out_msg`：用于写入响应消息的用户空间缓冲区。
- `outlen`：`out_msg` 的长度。

使用 `compat_copy_to_user(out_msg, buf, len)` 向用户空间写入响应。

### 控制（ctl1）

```c
// 签名
typedef long (*mod_ctl1call_t)(void *a1, void *a2, void *a3);

KPM_CTL1(my_control1_function);
```

用于内核内部的模块间通信的备用控制回调。

### 退出（Exit）

```c
// 签名
typedef long (*mod_exitcall_t)(void *reserved);

KPM_EXIT(my_exit_function);
```

模块卸载时调用。务必在此处解除在 `init` 中安装的所有 hook。

## 最小示例

```c
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>

KPM_NAME("kpm-hello-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module Example");

static long hello_init(const char *args, const char *event, void *reserved)
{
    pr_info("hello init, event: %s, args: %s\n", event, args);
    pr_info("kernelpatch version: %x\n", kpver);
    return 0;
}

static long hello_control0(const char *args, char *__user out_msg, int outlen)
{
    char echo[64] = "echo: ";
    strncat(echo, args, 48);
    compat_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;
}

static long hello_exit(void *reserved)
{
    pr_info("hello exit\n");
    return 0;
}

KPM_INIT(hello_init);
KPM_CTL0(hello_control0);
KPM_EXIT(hello_exit);
```

## 可用内核 API

以下所有函数和变量均由 KernelPatch 通过 `KP_EXPORT_SYMBOL` 导出，可在任意 KPM 中直接调用。

### 头文件

**KernelPatch 核心**（`kernel/include/`）：

| 头文件 | 用途 |
|--------|------|
| `<kpmodule.h>` | KPM 生命周期宏（`KPM_NAME`、`KPM_INIT` 等） |
| `<hook.h>` | Inline hook 和函数指针 hook API |
| `<hotpatch.h>` | 运行时指令热修补 |
| `<kpmalloc.h>` | KP 内存分配器（`kp_malloc`、`kp_free` 等） |
| `<log.h>` | 日志宏（`logkd`、`logkv` 等） |
| `<compiler.h>` | 编译器属性（`__noinline`、`__must_check` 等） |
| `<ktypes.h>` | 内核类型定义 |
| `<common.h>` | 通用工具函数 |
| `<predata.h>` / `<preset.h>` | KP 配置与魔数常量 |
| `<pgtable.h>` | 页表辅助函数 |

**KernelPatch patch 层**（`kernel/patch/include/`）：

| 头文件 | 用途 |
|--------|------|
| `<syscall.h>` | Syscall hook API（`hook_syscalln`、`fp_hook_syscalln` 等） |
| `<kputils.h>` | 用户空间拷贝辅助（`compat_copy_to_user` 等） |
| `<kstorage.h>` | 内核存储 API |
| `<sucompat.h>` | SU 允许列表管理 |
| `<accctl.h>` | 凭据切换（`commit_su`、`task_su` 等） |
| `<taskext.h>` | per-task 扩展存储（`task_ext`、`reg_task_local` 等） |
| `<ksyms.h>` | 内核结构体布局偏移 |
| `<uapi/scdefs.h>` | SuperCall 命令码与数据结构 |

**Linux 内核头文件**（以 stub 方式提供，由 kfunc 导出支撑）：

| 头文件 | 用途 |
|--------|------|
| `<linux/printk.h>` | `pr_info`、`pr_err`、`pr_warn`、`pr_debug` |
| `<linux/string.h>` | 字符串和内存函数 |
| `<linux/sched.h>` / `<linux/sched/task.h>` | `task_struct` |
| `<linux/cred.h>` | 凭据（`cred`、`current_cred`） |
| `<linux/uaccess.h>` | 用户空间内存访问 |
| `<asm/current.h>` | `current`（当前任务指针） |
| `<uapi/asm-generic/unistd.h>` | syscall 号（`__NR_*`） |

### 导出符号

#### 核心

| 符号 | 说明 |
|------|------|
| `kver` | 内核版本码（`major<<16 \| minor<<8 \| patch`） |
| `kpver` | KernelPatch 版本码 |
| `kallsyms_lookup_name(name)` | 按名称查找内核符号地址 |
| `kallsyms_on_each_symbol(fn, data)` | 遍历所有内核符号 |
| `printk(fmt, ...)` | 内核日志输出 |

#### Inline Hook（`<hook.h>`）

| 符号 | 说明 |
|------|------|
| `hook(func, replace, backup)` | 简单单一替换 hook |
| `unhook(func)` | 移除简单 hook |
| `hook_wrap(func, argno, before, after, udata)` | 链式 hook（多调用方安全） |
| `hook_unwrap_remove(func, before, after, remove)` | 移除链式 hook 项 |
| `hook_chain_add(chain, before, after, udata)` | 向已有链添加项 |
| `hook_chain_remove(chain, before, after)` | 从链中移除项 |
| `hook_prepare(hook)` / `hook_install(hook)` / `hook_uninstall(hook)` | 底层 hook 控制 |
| `fp_hook(fp_addr, replace, backup)` | 函数指针 hook |
| `fp_unhook(fp_addr, backup)` | 移除函数指针 hook |
| `fp_hook_wrap(fp_addr, argno, before, after, udata)` | 链式函数指针 hook |
| `fp_hook_unwrap(fp_addr, before, after)` | 移除链式函数指针 hook 项 |

`<hook.h>` 中以 static inline 方式提供了类型化便捷封装：`hook_wrap0`–`hook_wrap12` 和 `fp_hook_wrap0`–`fp_hook_wrap12`。

#### Syscall Hook（`<syscall.h>`）

| 符号 | 说明 |
|------|------|
| `hook_syscalln(nr, narg, before, after, udata)` | Hook syscall（自动选择策略） |
| `unhook_syscalln(nr, before, after)` | Unhook syscall |
| `hook_compat_syscalln(...)` / `unhook_compat_syscalln(...)` | 32 位兼容变体 |
| `inline_hook_syscalln(nr, narg, before, after, udata)` | Inline hook syscall 处理函数 |
| `inline_unhook_syscalln(nr, before, after)` | Unhook inline syscall |
| `fp_hook_syscalln(nr, narg, before, after, udata)` | 函数指针 syscall hook |
| `fp_unhook_syscalln(nr, before, after)` | Unhook fp syscall |
| `raw_syscall0(nr)` … `raw_syscall6(nr, ...)` | 在内核空间发起原始 syscall |
| `sys_call_table` / `compat_sys_call_table` | syscall 表指针 |
| `has_syscall_wrapper` / `has_config_compat` | 内核能力标志 |

#### 用户空间访问（`<kputils.h>`）

| 符号 | 说明 |
|------|------|
| `compat_copy_to_user(to, from, n)` | 向用户空间拷贝数据 |
| `compat_strncpy_from_user(dst, src, n)` | 从用户空间拷贝字符串 |
| `copy_to_user_stack(data, len)` | 将数据拷贝到用户栈 |
| `current_uid()` | 获取当前任务的 UID |
| `get_random_u64()` | 获取随机 64 位值 |

#### 内核存储（`<kstorage.h>`）

| 符号 | 说明 |
|------|------|
| `write_kstorage(gid, did, data, offset, len, is_user)` | 写入存储条目 |
| `read_kstorage(gid, did, data, offset, len, is_user)` | 读取存储条目 |
| `get_kstorage(gid, did)` | 获取存储条目指针（需在 RCU 读锁内使用） |
| `on_each_kstorage_elem(gid, cb, udata)` | 遍历组内所有条目 |
| `list_kstorage_ids(gid, ids, idslen, is_user)` | 列出组内所有条目 ID |
| `remove_kstorage(gid, did)` | 移除存储条目 |

#### SU / 访问控制（`<sucompat.h>`、`<accctl.h>`）

| 符号 | 说明 |
|------|------|
| `commit_su(uid, sctx)` | 将当前任务凭据切换到 `uid`，SELinux 上下文为 `sctx` |
| `task_su(pid, to_uid, sctx)` | 切换指定任务的凭据 |
| `is_su_allow_uid(uid)` | 检查某 UID 是否拥有 SU 权限 |
| `su_add_allow_uid(uid, to_uid, sctx)` | 授予某 UID 的 SU 权限 |
| `su_remove_allow_uid(uid)` | 撤销某 UID 的 SU 权限 |
| `su_allow_uid_nums()` | 统计拥有 SU 权限的 UID 数量 |
| `su_allow_uids(is_user, out_uids, out_num)` | 列出拥有 SU 权限的 UID |
| `su_allow_uid_profile(is_user, uid, profile)` | 获取某 UID 的 SU profile |
| `su_reset_path(path)` / `su_get_path()` | 获取/设置 su 二进制路径 |
| `set_ap_mod_exclude(uid, exclude)` | 设置某 UID 的模块排除标志 |
| `get_ap_mod_exclude(uid)` | 获取某 UID 的模块排除标志 |
| `list_ap_mod_exclude(uids, len)` | 列出所有设置了模块排除标志的 UID |

#### 热修补（`<hotpatch.h>`）

| 符号 | 说明 |
|------|------|
| `hotpatch(addrs[], values[], cnt)` | 原子化修补多条指令 |
| `hotpatch_nosync(addr, value)` | 无同步修补单条指令 |

#### 字符串与内存（通过 `<linux/string.h>`）

以下标准 C 字符串和内存函数以 kfunc 导出方式可用：
`strcpy`、`strncpy`、`strlcpy`、`strscpy`、`strcat`、`strncat`、`strcmp`、`strncmp`、
`strchr`、`strrchr`、`strlen`、`strnlen`、`strstr`、`strnstr`、`strspn`、`strcspn`、
`memset`、`memcpy`、`memmove`、`memcmp`、`memchr`、`memchr_inv`、
`sprintf`、`snprintf`、`vsnprintf`、`kasprintf`、`sscanf` 等。

#### Task 扩展（`<taskext.h>`）

| 符号 | 说明 |
|------|------|
| `task_ext_size` | `task_ext` 结构体当前大小 |
| `reg_task_local(size)` | 注册一个 per-task（线程局部）变量槽 |
| `has_task_local(ext, offset)` | 检查某 task-local 变量是否已注册 |
| `task_local_ptr(ext, offset)` | 获取 task-local 变量的指针 |

#### 内核结构体偏移（`<ksyms.h>`）

| 符号 | 说明 |
|------|------|
| `task_struct_offset` | `task_struct` 内各字段偏移 |
| `cred_offset` | `cred` 内各字段偏移 |
| `mm_struct_offset` | `mm_struct` 内各字段偏移 |
| `thread_size` / `thread_info_in_task` | 线程栈布局信息 |

## 编译 KPM

KPM 以裸机 ARM64 ELF 文件形式编译，需要 `aarch64-none-elf-` 工具链：

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kpms/demo-hello
make
```

输出的 `.kpm` ELF 文件可通过 `sc_kpm_load()` 加载。

详见 [build.md](./build.md) 中的工具链配置说明。

## 不使用内核源码树开发

KPM 无需内核源码即可调用任意内核函数：

1. 用 `kallsyms_lookup_name("function_name")` 获取函数地址。
2. 将返回的地址转换为相应的函数指针类型。
3. 直接调用。

```c
static int (*__do_something)(int arg) = NULL;

static long my_init(const char *args, const char *event, void *reserved)
{
    __do_something = (typeof(__do_something))kallsyms_lookup_name("do_something");
    if (!__do_something) {
        pr_err("symbol not found\n");
        return -1;
    }
    __do_something(42);
    return 0;
}
```

## 从用户空间加载和管理模块

使用 `supercall.h` 中的 API 在运行时管理 KPM：

```c
#include "supercall.h"

// 加载模块
sc_kpm_load(key, "/data/local/tmp/my.kpm", "init_args", NULL);

// 发送控制消息
char response[256];
sc_kpm_control(key, "kpm-hello-demo", "ping", response, sizeof(response));

// 卸载模块
sc_kpm_unload(key, "kpm-hello-demo", NULL);

// 列出已加载模块
char names[1024];
sc_kpm_list(key, names, sizeof(names));

// 获取模块信息
char info[1024];
sc_kpm_info(key, "kpm-hello-demo", info, sizeof(info));
```

## 示例工程

仓库 `kpms/` 目录下提供了四个示例：

- [`demo-hello`](../../kpms/demo-hello/) — 基础生命周期回调与控制消息示例。
- [`demo-inlinehook`](../../kpms/demo-inlinehook/) — 使用 `hook_wrap` 内联 hook 内核函数。详见 [inline-hook.md](./inline-hook.md)。
- [`demo-syscallhook`](../../kpms/demo-syscallhook/) — 使用 `fp_hook_syscalln` hook 系统调用。详见 [syscall-hook.md](./syscall-hook.md)。
- [`demo-tasklocal`](../../kpms/demo-tasklocal/) — 使用 per-task 本地存储。
