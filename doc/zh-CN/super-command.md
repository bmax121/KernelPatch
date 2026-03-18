# Super 命令

Super 命令通过 hook `truncate` syscall 实现。当以有效的 superkey（或 `su`）作为第一个参数执行 `/system/bin/truncate` 时，KernelPatch 会拦截调用并执行所请求的命令。

## 基本用法

```
truncate <superkey|su> [-u UID] [-Z SCONTEXT] [COMMAND [...]]
```

第一个参数为认证凭据：
- **superkey** — 配置的 superkey，授予所有命令的完整访问权限。
- **su** — 若调用方进程的 UID 已被授予 SU 权限，可使用字符串 `"su"`；此时只能使用 `sumgr` 及不需要 superkey 的命令。

若不指定命令，则以指定凭据启动一个交互式 shell。

## 选项

选项出现在命令之前，用于修改执行时使用的凭据：

| 选项 | 说明 |
|------|------|
| `-u <UID>` | 执行命令前切换到指定 UID |
| `-Z <SCONTEXT>` | 切换到指定的 SELinux 安全上下文 |

## 命令

### `help`

打印完整的用法说明。

```
truncate <superkey> help
```

### `version`

以十六进制打印内核版本和 KernelPatch 版本。

```
truncate <superkey> version
```

输出格式：`<内核版本十六进制>,<KP版本十六进制>`
示例：`50a0a,a06` 表示内核 5.10.10，KernelPatch 0.10.6。

### `buildtime`

打印 KernelPatch 的编译时间戳。

```
truncate <superkey> buildtime
```

### `-c <COMMAND> [...]`

将命令字符串传给默认 shell（`/system/bin/sh`）执行。

```
truncate <superkey> -c "id"
truncate <superkey> -u 0 -Z u:r:su:s0 -c "ls /data"
```

### `exec <PATH> [...]`

按完整路径直接执行程序。

```
truncate <superkey> exec /data/local/tmp/my_program arg1 arg2
```

### `sumgr` — SU 权限管理

管理哪些 UID 被允许使用 SU。

```
truncate <superkey|su> sumgr <子命令> [...]
```

| 子命令 | 参数 | 说明 |
|--------|------|------|
| `grant` | `<UID> [TO_UID [SCONTEXT]]` | 授予 UID 的 SU 权限，切换到 TO_UID 和 SCONTEXT |
| `revoke` | `<UID>` | 撤销 UID 的 SU 权限 |
| `num` | | 获取拥有 SU 权限的 UID 数量 |
| `list` | | 列出所有拥有 SU 权限的 UID |
| `profile` | `<UID>` | 获取指定 UID 的 SU profile（to_uid、scontext） |
| `path` | `[PATH]` | 获取或设置 su 二进制路径（长度须为 2–127） |
| `sctx` | `[SCONTEXT]` | 获取或设置全允许 SELinux 上下文 |
| `exclude` | `<UID> [1\|0]` | 获取或设置某 UID 的模块排除策略（仅 Android） |
| `exclude_list` | | 列出所有被排除的 UID（仅 Android） |

示例：

```shell
# 授予 UID 2000 root 权限，切换到 uid 0，使用默认 scontext
truncate <superkey> sumgr grant 2000

# 授予 UID 2000，切换到 uid 0，使用自定义 scontext
truncate <superkey> sumgr grant 2000 0 u:r:su:s0

# 撤销
truncate <superkey> sumgr revoke 2000

# 查看 UID 2000 的 profile
truncate <superkey> sumgr profile 2000

# 修改 su 二进制路径
truncate <superkey> sumgr path /data/local/tmp/mysu

# 设置全允许 SELinux 上下文
truncate <superkey> sumgr sctx u:r:su:s0
```

### `module` — KPM 模块管理

需要 superkey 认证。

```
truncate <superkey> module <子命令> [...]
```

| 子命令 | 参数 | 说明 |
|--------|------|------|
| `load` | `<KPM_PATH> [KPM_ARGS]` | 从 KPM_PATH 加载模块，KPM_ARGS 传给其 init |
| `unload` | `<KPM_NAME>` | 卸载名为 KPM_NAME 的模块 |
| `ctl0` | `<KPM_NAME> <CTL_ARGS>` | 向模块发送控制字符串 |
| `num` | | 获取当前已加载模块数量 |
| `list` | | 列出所有已加载模块名称 |
| `info` | `<KPM_NAME>` | 获取指定模块的详细信息 |

示例：

```shell
truncate <superkey> module load /data/local/tmp/my.kpm "init args"
truncate <superkey> module ctl0 my-module "ping"
truncate <superkey> module info my-module
truncate <superkey> module unload my-module
truncate <superkey> module list
```

### `key` — Superkey 管理

需要 superkey 认证。

```
truncate <superkey> key <子命令> [...]
```

| 子命令 | 参数 | 说明 |
|--------|------|------|
| `get` | | 打印当前 superkey |
| `set` | `<NEW_KEY>` | 将 superkey 修改为 NEW_KEY |
| `hash` | `enable\|disable` | 启用或禁用 root superkey 的哈希验证 |

示例：

```shell
truncate <superkey> key get
truncate <superkey> key set mynewsecretkey
truncate <superkey> key hash enable
```

### `event`

向 KernelPatch 上报用户事件。

```
truncate <superkey|su> event <EVENT> [DATA]
```

### `bootlog`

打印 KernelPatch 的启动日志。

```
truncate <superkey> bootlog
```
