# KernelPatch Module (KPM)

A KernelPatch Module (KPM) is an ELF file that KernelPatch loads and executes within kernel space. KPMs allow you to extend or modify kernel behavior dynamically, similar to kernel modules, but without requiring kernel source code or a running build system.

## Module Metadata

Every KPM must declare metadata using the following macros (defined in `<kpmodule.h>`):

```c
KPM_NAME("my-module");           // Unique module name (max 32 bytes)
KPM_VERSION("1.0.0");            // Version string (max 32 bytes)
KPM_LICENSE("GPL v2");           // License (max 32 bytes)
KPM_AUTHOR("author");            // Author name (max 32 bytes)
KPM_DESCRIPTION("description");  // Description (max 512 bytes)
```

`KPM_NAME` must be unique among all loaded modules—it is used as the identifier for control and unload operations.

## Lifecycle Callbacks

A KPM registers callbacks for initialization, control, and cleanup:

### Init

```c
// Signature
typedef long (*mod_initcall_t)(const char *args, const char *event, void *reserved);

KPM_INIT(my_init_function);
```

Called when the module is loaded. Parameters:

- `args`: Argument string passed via `sc_kpm_load()`.
- `event`: The triggering event name (e.g., `"load"`, or a kernel event string if loaded at boot).
- `reserved`: Reserved, always `NULL`.

Return `0` on success. A non-zero return indicates initialization failure.

### Control (ctl0)

```c
// Signature
typedef long (*mod_ctl0call_t)(const char *ctl_args, char *__user out_msg, int outlen);

KPM_CTL0(my_control0_function);
```

Called when userspace invokes `sc_kpm_control()`. Parameters:

- `ctl_args`: Control argument string.
- `out_msg`: Userspace buffer for the response message.
- `outlen`: Length of `out_msg`.

Use `compat_copy_to_user(out_msg, buf, len)` to write the response.

### Control (ctl1)

```c
// Signature
typedef long (*mod_ctl1call_t)(void *a1, void *a2, void *a3);

KPM_CTL1(my_control1_function);
```

An alternative control callback for internal kernel-to-module communication.

### Exit

```c
// Signature
typedef long (*mod_exitcall_t)(void *reserved);

KPM_EXIT(my_exit_function);
```

Called when the module is unloaded. Always unhook any functions or syscalls installed in `init` here.

## Minimal Example

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

## Available Kernel APIs

All functions and variables listed below are exported by KernelPatch via `KP_EXPORT_SYMBOL` and are directly callable from any KPM.

### Headers

Include these headers in your KPM source to access the corresponding APIs:

**KernelPatch core** (`kernel/include/`):

| Header | Purpose |
|--------|---------|
| `<kpmodule.h>` | KPM lifecycle macros (`KPM_NAME`, `KPM_INIT`, etc.) |
| `<hook.h>` | Inline hook and function-pointer hook API |
| `<hotpatch.h>` | Live instruction patching |
| `<kpmalloc.h>` | KP memory allocator (`kp_malloc`, `kp_free`, etc.) |
| `<log.h>` | Logging macros (`logkd`, `logkv`, etc.) |
| `<compiler.h>` | Compiler attributes (`__noinline`, `__must_check`, etc.) |
| `<ktypes.h>` | Kernel type definitions |
| `<common.h>` | Misc common utilities |
| `<predata.h>` / `<preset.h>` | KP configuration and magic constants |
| `<pgtable.h>` | Page table helpers |

**KernelPatch patch layer** (`kernel/patch/include/`):

| Header | Purpose |
|--------|---------|
| `<syscall.h>` | Syscall hook API (`hook_syscalln`, `fp_hook_syscalln`, etc.) |
| `<kputils.h>` | Userspace copy helpers (`compat_copy_to_user`, etc.) |
| `<kstorage.h>` | Kernel storage API |
| `<sucompat.h>` | SU allow-list management |
| `<accctl.h>` | Credential switching (`commit_su`, `task_su`, etc.) |
| `<taskext.h>` | Per-task extension storage (`task_ext`, `reg_task_local`, etc.) |
| `<ksyms.h>` | Kernel struct layout offsets |
| `<uapi/scdefs.h>` | SuperCall command codes and data structures |

**Linux kernel headers** (provided as stubs, backed by kfunc exports):

| Header | Purpose |
|--------|---------|
| `<linux/printk.h>` | `pr_info`, `pr_err`, `pr_warn`, `pr_debug` |
| `<linux/string.h>` | String and memory functions |
| `<linux/sched.h>` / `<linux/sched/task.h>` | `task_struct` |
| `<linux/cred.h>` | Credentials (`cred`, `current_cred`) |
| `<linux/uaccess.h>` | Userspace memory access |
| `<asm/current.h>` | `current` (current task pointer) |
| `<uapi/asm-generic/unistd.h>` | Syscall numbers (`__NR_*`) |

### Exported Symbols

#### Core

| Symbol | Description |
|--------|-------------|
| `kver` | Kernel version code (`major<<16 \| minor<<8 \| patch`) |
| `kpver` | KernelPatch version code |
| `kallsyms_lookup_name(name)` | Look up a kernel symbol address by name |
| `kallsyms_on_each_symbol(fn, data)` | Iterate all kernel symbols |
| `printk(fmt, ...)` | Kernel log output |

#### Inline Hook (`<hook.h>`)

| Symbol | Description |
|--------|-------------|
| `hook(func, replace, backup)` | Simple single-replacement hook |
| `unhook(func)` | Remove a simple hook |
| `hook_wrap(func, argno, before, after, udata)` | Chain hook (multiple callers safe) |
| `hook_unwrap_remove(func, before, after, remove)` | Remove a chain hook item |
| `hook_chain_add(chain, before, after, udata)` | Add item to an existing chain |
| `hook_chain_remove(chain, before, after)` | Remove item from a chain |
| `hook_prepare(hook)` / `hook_install(hook)` / `hook_uninstall(hook)` | Low-level hook control |
| `fp_hook(fp_addr, replace, backup)` | Function-pointer hook |
| `fp_unhook(fp_addr, backup)` | Remove a function-pointer hook |
| `fp_hook_wrap(fp_addr, argno, before, after, udata)` | Chain function-pointer hook |
| `fp_hook_unwrap(fp_addr, before, after)` | Remove a chain function-pointer hook item |

Typed convenience wrappers `hook_wrap0`–`hook_wrap12` and `fp_hook_wrap0`–`fp_hook_wrap12` are defined as static inlines in `<hook.h>`.

#### Syscall Hook (`<syscall.h>`)

| Symbol | Description |
|--------|-------------|
| `hook_syscalln(nr, narg, before, after, udata)` | Hook a syscall (auto strategy) |
| `unhook_syscalln(nr, before, after)` | Unhook a syscall |
| `hook_compat_syscalln(...)` / `unhook_compat_syscalln(...)` | 32-bit compat variants |
| `inline_hook_syscalln(nr, narg, before, after, udata)` | Inline-hook a syscall handler |
| `inline_unhook_syscalln(nr, before, after)` | Unhook inline syscall |
| `fp_hook_syscalln(nr, narg, before, after, udata)` | Function-pointer syscall hook |
| `fp_unhook_syscalln(nr, before, after)` | Unhook fp syscall |
| `raw_syscall0(nr)` … `raw_syscall6(nr, ...)` | Issue a raw syscall from kernel space |
| `sys_call_table` / `compat_sys_call_table` | Syscall table pointers |
| `has_syscall_wrapper` / `has_config_compat` | Kernel capability flags |

#### Userspace Access (`<kputils.h>`)

| Symbol | Description |
|--------|-------------|
| `compat_copy_to_user(to, from, n)` | Copy data to userspace |
| `compat_strncpy_from_user(dst, src, n)` | Copy string from userspace |
| `copy_to_user_stack(data, len)` | Copy data onto the user stack |
| `current_uid()` | Get the UID of the current task |
| `get_random_u64()` | Get a random 64-bit value |

#### Kernel Storage (`<kstorage.h>`)

| Symbol | Description |
|--------|-------------|
| `write_kstorage(gid, did, data, offset, len, is_user)` | Write a storage entry |
| `read_kstorage(gid, did, data, offset, len, is_user)` | Read a storage entry |
| `get_kstorage(gid, did)` | Get a storage entry pointer (within RCU read lock) |
| `on_each_kstorage_elem(gid, cb, udata)` | Iterate entries in a group |
| `list_kstorage_ids(gid, ids, idslen, is_user)` | List entry IDs in a group |
| `remove_kstorage(gid, did)` | Remove a storage entry |

#### SU / Access Control (`<sucompat.h>`, `<accctl.h>`)

| Symbol | Description |
|--------|-------------|
| `commit_su(uid, sctx)` | Switch current task credentials to `uid` with SELinux context `sctx` |
| `task_su(pid, to_uid, sctx)` | Switch credentials of a specific task |
| `is_su_allow_uid(uid)` | Check if a UID has SU access |
| `su_add_allow_uid(uid, to_uid, sctx)` | Grant SU access to a UID |
| `su_remove_allow_uid(uid)` | Revoke SU access from a UID |
| `su_allow_uid_nums()` | Count UIDs with SU access |
| `su_allow_uids(is_user, out_uids, out_num)` | List UIDs with SU access |
| `su_allow_uid_profile(is_user, uid, profile)` | Get SU profile for a UID |
| `su_reset_path(path)` / `su_get_path()` | Get/set the su binary path |
| `set_ap_mod_exclude(uid, exclude)` | Set module exclude flag for a UID |
| `get_ap_mod_exclude(uid)` | Get module exclude flag for a UID |
| `list_ap_mod_exclude(uids, len)` | List all UIDs with module exclude flag set |

#### Hot Patch (`<hotpatch.h>`)

| Symbol | Description |
|--------|-------------|
| `hotpatch(addrs[], values[], cnt)` | Atomically patch multiple instructions |
| `hotpatch_nosync(addr, value)` | Patch a single instruction without sync |

#### String and Memory (via `<linux/string.h>`)

Standard C string and memory functions are available as kfunc-backed exports:
`strcpy`, `strncpy`, `strlcpy`, `strscpy`, `strcat`, `strncat`, `strcmp`, `strncmp`,
`strchr`, `strrchr`, `strlen`, `strnlen`, `strstr`, `strnstr`, `strspn`, `strcspn`,
`memset`, `memcpy`, `memmove`, `memcmp`, `memchr`, `memchr_inv`,
`sprintf`, `snprintf`, `vsnprintf`, `kasprintf`, `sscanf`, and more.

#### Task Extension (`<taskext.h>`)

| Symbol | Description |
|--------|-------------|
| `task_ext_size` | Current size of `task_ext` struct |
| `reg_task_local(size)` | Register a per-task (thread-local) variable slot |
| `has_task_local(ext, offset)` | Check if a task-local variable is registered |
| `task_local_ptr(ext, offset)` | Get pointer to a task-local variable |

#### Kernel Struct Offsets (`<ksyms.h>`)

| Symbol | Description |
|--------|-------------|
| `task_struct_offset` | Offsets within `task_struct` |
| `cred_offset` | Offsets within `cred` |
| `mm_struct_offset` | Offsets within `mm_struct` |
| `thread_size` / `thread_info_in_task` | Thread stack layout info |

## Building a KPM

KPMs are built as bare-metal ARM64 ELF files. You need the `aarch64-none-elf-` toolchain.

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kpms/demo-hello
make
```

The output is a `.kpm` ELF file that can be loaded via `sc_kpm_load()`.

See [build.md](./build.md) for full toolchain setup instructions.

## Working Without Kernel Source

KPMs can run without access to the kernel source tree. To call arbitrary kernel functions:

1. Use `kallsyms_lookup_name("function_name")` to get the function address.
2. Cast the returned address to the appropriate function pointer type.
3. Call it directly.

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

## Loading and Managing Modules

Use the SuperCall API from userspace to manage KPMs at runtime:

```c
#include "supercall.h"

// Load a module
sc_kpm_load(key, "/data/local/tmp/my.kpm", "init_args", NULL);

// Send a control message
char response[256];
sc_kpm_control(key, "kpm-hello-demo", "ping", response, sizeof(response));

// Unload a module
sc_kpm_unload(key, "kpm-hello-demo", NULL);

// List loaded modules
char names[1024];
sc_kpm_list(key, names, sizeof(names));

// Get module info
char info[1024];
sc_kpm_info(key, "kpm-hello-demo", info, sizeof(info));
```

## Demo Examples

Four example KPMs are included in the repository under `kpms/`:

- [`demo-hello`](../../kpms/demo-hello/) — Basic lifecycle callbacks and control messaging.
- [`demo-inlinehook`](../../kpms/demo-inlinehook/) — Inline hooking a kernel function with `hook_wrap`. See [inline-hook.md](./inline-hook.md).
- [`demo-syscallhook`](../../kpms/demo-syscallhook/) — Hooking a syscall with `fp_hook_syscalln`. See [syscall-hook.md](./syscall-hook.md).
- [`demo-tasklocal`](../../kpms/demo-tasklocal/) — Using per-task local storage.
