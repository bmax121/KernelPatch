# Super 系统调用

KernelPatch 通过一个复用的系统调用（**SuperCall**）向用户空间暴露所有功能。从权限提升到模块管理，所有操作都通过这一个 syscall 以不同的命令码完成。

## 机制

SuperCall 复用 Linux syscall 号 **45**（在大多数 Linux/Android 系统上即 `truncate`）：

```c
#define __NR_supercall 45
```

第一个参数始终是 **superkey** 字符串，第二个参数编码了 KernelPatch 版本和命令码，其余参数取决于具体命令。

命令参数的编码格式：

```
[31:16] = 0x1158（魔数）
[15:0]  = 命令码
[63:32] = KernelPatch 版本（major<<16 | minor<<8 | patch）
```

实际使用时，直接调用 `supercall.h` 中的封装函数，编码由其自动处理。

## 认证

每次 SuperCall 都需要以 **superkey** 作为第一个参数。superkey 是一个最长 64 字节的以 null 结尾的字符串（`SUPERCALL_KEY_MAX_LEN`）。

特权操作（内核日志、模块管理、密钥管理）需要真实的 superkey。部分只读操作在调用方 UID 已被授予 SU 权限时也接受字符串 `"su"`。

## 使用 C API

在用户空间程序中包含 `user/supercall.h`，所有函数的调用模式为：

```c
long result = sc_<command>(key, ...);
```

### 检测是否安装

```c
// 若 KernelPatch 已激活，返回 SUPERCALL_HELLO_MAGIC（0x11581158）
long sc_hello(const char *key);

// 便捷封装，返回 bool
bool sc_ready(const char *key);
```

### 版本信息

```c
// KernelPatch 版本（编码为 major<<16 | minor<<8 | patch）
uint32_t sc_kp_ver(const char *key);

// Linux 内核版本（编码方式相同）
uint32_t sc_k_ver(const char *key);

// KernelPatch 编译时间戳字符串
long sc_kp_buildtime(const char *key, char *out_buildtime, int outlen);
```

### 内核日志

```c
// 通过内核 printk 打印消息
long sc_klog(const char *key, const char *msg);
```

### 权限提升（SU）

`su_profile` 结构体控制新的凭据：

```c
struct su_profile {
    uid_t uid;                             // 来源 UID（谁被允许提权）
    uid_t to_uid;                          // 目标 UID（通常为 0，即 root）
    char scontext[SUPERCALL_SCONTEXT_LEN]; // SELinux 上下文（为空则绕过 SELinux）
};
```

```c
// 将当前线程切换为 profile 中指定的凭据
long sc_su(const char *key, struct su_profile *profile);

// 将指定 TID 的线程切换为 profile 中指定的凭据
long sc_su_task(const char *key, pid_t tid, struct su_profile *profile);

// 永久授予某 UID 的 SU 权限
long sc_su_grant_uid(const char *key, struct su_profile *profile);

// 撤销某 UID 的 SU 权限
long sc_su_revoke_uid(const char *key, uid_t uid);

// 获取拥有 SU 权限的 UID 数量
long sc_su_uid_nums(const char *key);

// 列出拥有 SU 权限的 UID
long sc_su_allow_uids(const char *key, uid_t *buf, int num);

// 获取指定 UID 的 SU profile
long sc_su_uid_profile(const char *key, uid_t uid, struct su_profile *out_profile);
```

### SU 路径管理

```c
// 获取当前 su 二进制路径
long sc_su_get_path(const char *key, char *out_path, int path_len);

// 设置 su 二进制路径
long sc_su_reset_path(const char *key, const char *path);
```

### SELinux 上下文管理

```c
// 获取当前配置的全允许 SELinux 上下文
long sc_su_get_all_allow_sctx(const char *key, char *out_sctx, int sctx_len);

// 设置全允许 SELinux 上下文（传空字符串则清除）
long sc_su_reset_all_allow_sctx(const char *key, const char *sctx);
```

### 安全模式

```c
// 若系统处于安全模式启动，返回非零值
long sc_su_get_safemode(const char *key);
```

### KPM 模块管理

```c
// 从指定路径加载 KPM
long sc_kpm_load(const char *key, const char *path, const char *args, void *reserved);

// 向已加载模块发送控制字符串
long sc_kpm_control(const char *key, const char *name, const char *ctl_args,
                    char *out_msg, long outlen);

// 按名称卸载模块
long sc_kpm_unload(const char *key, const char *name, void *reserved);

// 获取已加载模块数量
long sc_kpm_nums(const char *key);

// 列出已加载模块名称（换行分隔）
long sc_kpm_list(const char *key, char *names_buf, int buf_len);

// 获取模块信息字符串
long sc_kpm_info(const char *key, const char *name, char *buf, int buf_len);
```

### 内核存储

内核存储提供一个持久化的内核空间键值存储，按组 ID（gid）和数据 ID（did）组织：

```c
// 写入存储条目
long sc_kstorage_write(const char *key, int gid, long did, void *data, int offset, int dlen);

// 读取存储条目
long sc_kstorage_read(const char *key, int gid, long did, void *out_data, int offset, int dlen);

// 列出某组内的所有数据 ID
long sc_kstorage_list_ids(const char *key, int gid, long *ids, int ids_len);

// 移除存储条目
long sc_kstorage_remove(const char *key, int gid, long did);
```

保留的组 ID：

| 组 ID | 常量 | 用途 |
|-------|------|------|
| 0 | `KSTORAGE_SU_LIST_GROUP` | SU 允许列表 |
| 1 | `KSTORAGE_EXCLUDE_LIST_GROUP` | 模块排除列表 |

### Superkey 管理

```c
// 获取当前 superkey
long sc_skey_get(const char *key, char *out_key, int outlen);

// 修改 superkey
long sc_skey_set(const char *key, const char *new_key);

// 启用或禁用 root superkey 的哈希验证
long sc_skey_root_enable(const char *key, bool enable);
```

## 命令码速查表

| 命令 | 码值 | 说明 |
|------|------|------|
| `SUPERCALL_HELLO` | 0x1000 | Ping / 检测是否安装 |
| `SUPERCALL_KLOG` | 0x1004 | 内核日志消息 |
| `SUPERCALL_BUILD_TIME` | 0x1007 | KP 编译时间戳 |
| `SUPERCALL_KERNELPATCH_VER` | 0x1008 | KP 版本 |
| `SUPERCALL_KERNEL_VER` | 0x1009 | 内核版本 |
| `SUPERCALL_SKEY_GET` | 0x100a | 获取 superkey |
| `SUPERCALL_SKEY_SET` | 0x100b | 设置 superkey |
| `SUPERCALL_SKEY_ROOT_ENABLE` | 0x100c | 启用 root 哈希验证 |
| `SUPERCALL_SU` | 0x1010 | 当前线程提权 |
| `SUPERCALL_SU_TASK` | 0x1011 | 指定线程提权 |
| `SUPERCALL_KPM_LOAD` | 0x1020 | 加载 KPM |
| `SUPERCALL_KPM_UNLOAD` | 0x1021 | 卸载 KPM |
| `SUPERCALL_KPM_CONTROL` | 0x1022 | 控制 KPM |
| `SUPERCALL_KPM_NUMS` | 0x1030 | KPM 数量 |
| `SUPERCALL_KPM_LIST` | 0x1031 | 列出 KPM 名称 |
| `SUPERCALL_KPM_INFO` | 0x1032 | KPM 信息 |
| `SUPERCALL_KSTORAGE_WRITE` | 0x1041 | 写入存储 |
| `SUPERCALL_KSTORAGE_READ` | 0x1042 | 读取存储 |
| `SUPERCALL_KSTORAGE_LIST_IDS` | 0x1043 | 列出存储 ID |
| `SUPERCALL_KSTORAGE_REMOVE` | 0x1044 | 移除存储 |
| `SUPERCALL_SU_GRANT_UID` | 0x1100 | 授予 UID SU 权限 |
| `SUPERCALL_SU_REVOKE_UID` | 0x1101 | 撤销 UID SU 权限 |
| `SUPERCALL_SU_NUMS` | 0x1102 | SU UID 数量 |
| `SUPERCALL_SU_LIST` | 0x1103 | 列出 SU UID |
| `SUPERCALL_SU_PROFILE` | 0x1104 | 获取 UID SU profile |
| `SUPERCALL_SU_GET_ALLOW_SCTX` | 0x1105 | 获取全允许 SELinux 上下文 |
| `SUPERCALL_SU_SET_ALLOW_SCTX` | 0x1106 | 设置全允许 SELinux 上下文 |
| `SUPERCALL_SU_GET_PATH` | 0x1110 | 获取 SU 二进制路径 |
| `SUPERCALL_SU_RESET_PATH` | 0x1111 | 设置 SU 二进制路径 |
| `SUPERCALL_SU_GET_SAFEMODE` | 0x1112 | 检查安全模式 |

## 示例：检测 KernelPatch 并获取版本

```c
#include <stdio.h>
#include "supercall.h"

int main(void)
{
    const char *key = "mysuperkey";

    if (!sc_ready(key)) {
        printf("KernelPatch 未安装\n");
        return 1;
    }

    uint32_t kp_ver = sc_kp_ver(key);
    uint32_t k_ver  = sc_k_ver(key);

    printf("KernelPatch 版本: %d.%d.%d\n",
           (kp_ver >> 16) & 0xff,
           (kp_ver >> 8) & 0xff,
           kp_ver & 0xff);

    printf("内核版本: %d.%d.%d\n",
           (k_ver >> 16) & 0xff,
           (k_ver >> 8) & 0xff,
           k_ver & 0xff);

    return 0;
}
```

## 示例：将当前进程提权为 root

```c
#include "supercall.h"

int grant_root(const char *key)
{
    struct su_profile profile = {
        .uid    = getuid(),
        .to_uid = 0,
        .scontext = "u:r:su:s0",
    };
    return (int)sc_su(key, &profile);
}
```
