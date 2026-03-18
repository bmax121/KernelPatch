# Super System Call

KernelPatch exposes its functionality to userspace through a single multiplexed system call called **SuperCall**. All operations—from privilege escalation to module management—are performed by invoking this one syscall with different command codes.

## Mechanism

SuperCall reuses Linux syscall number **45** (`truncate` on most Linux/Android systems):

```c
#define __NR_supercall 45
```

The first argument is always a **superkey** string. The second argument encodes the KernelPatch version and command code. Additional arguments depend on the specific command.

The command argument is constructed as:

```
[31:16] = 0x1158 (magic)
[15:0]  = command code
[63:32] = KernelPatch version (major<<16 | minor<<8 | patch)
```

In practice, use the `supercall.h` wrapper functions—they handle encoding automatically.

## Authentication

Every SuperCall requires a **superkey** as its first argument. The superkey is a null-terminated string up to 64 bytes (`SUPERCALL_KEY_MAX_LEN`).

Privileged operations (kernel logging, module management, key management) require the actual superkey. Some read-only operations also accept the string `"su"` if the calling process's UID has been granted SU access.

## Using the C API

Include `user/supercall.h` in your userspace program. All functions follow the pattern:

```c
long result = sc_<command>(key, ...);
```

### Detection

```c
// Returns SUPERCALL_HELLO_MAGIC (0x11581158) if KernelPatch is active
long sc_hello(const char *key);

// Convenience wrapper returning bool
bool sc_ready(const char *key);
```

### Version Information

```c
// KernelPatch version (encoded as major<<16 | minor<<8 | patch)
uint32_t sc_kp_ver(const char *key);

// Linux kernel version (same encoding)
uint32_t sc_k_ver(const char *key);

// KernelPatch build timestamp string
long sc_kp_buildtime(const char *key, char *out_buildtime, int outlen);
```

### Kernel Logging

```c
// Print a message via kernel printk
long sc_klog(const char *key, const char *msg);
```

### Privilege Escalation (SU)

The `su_profile` structure controls the new credentials:

```c
struct su_profile {
    uid_t uid;                          // Source UID (who is allowed to escalate)
    uid_t to_uid;                       // Target UID to switch to (usually 0 for root)
    char scontext[SUPERCALL_SCONTEXT_LEN]; // SELinux context (empty = bypass SELinux)
};
```

```c
// Switch the current thread to the credentials in profile
long sc_su(const char *key, struct su_profile *profile);

// Switch a specific thread (by TID) to the credentials in profile
long sc_su_task(const char *key, pid_t tid, struct su_profile *profile);

// Permanently grant SU access for a UID
long sc_su_grant_uid(const char *key, struct su_profile *profile);

// Revoke SU access for a UID
long sc_su_revoke_uid(const char *key, uid_t uid);

// Get number of UIDs with SU access
long sc_su_uid_nums(const char *key);

// List UIDs with SU access
long sc_su_allow_uids(const char *key, uid_t *buf, int num);

// Get SU profile for a specific UID
long sc_su_uid_profile(const char *key, uid_t uid, struct su_profile *out_profile);
```

### SU Path Management

```c
// Get path of the current 'su' binary
long sc_su_get_path(const char *key, char *out_path, int path_len);

// Set path of the 'su' binary
long sc_su_reset_path(const char *key, const char *path);
```

### SELinux Context Management

```c
// Get the currently configured all-allow SELinux context
long sc_su_get_all_allow_sctx(const char *key, char *out_sctx, int sctx_len);

// Set an all-allow SELinux context (empty string to clear)
long sc_su_reset_all_allow_sctx(const char *key, const char *sctx);
```

### Safe Mode

```c
// Returns non-zero if the system is booted in safe mode
long sc_su_get_safemode(const char *key);
```

### KPM Module Management

```c
// Load a KPM from the given file path
long sc_kpm_load(const char *key, const char *path, const char *args, void *reserved);

// Send a control string to a loaded module
long sc_kpm_control(const char *key, const char *name, const char *ctl_args,
                    char *out_msg, long outlen);

// Unload a module by name
long sc_kpm_unload(const char *key, const char *name, void *reserved);

// Get the number of loaded modules
long sc_kpm_nums(const char *key);

// List loaded module names (newline-separated)
long sc_kpm_list(const char *key, char *names_buf, int buf_len);

// Get info string for a module
long sc_kpm_info(const char *key, const char *name, char *buf, int buf_len);
```

### Kernel Storage

Kernel storage provides a persistent key-value store in kernel space, organized by group ID and data ID:

```c
// Write data to a storage slot
long sc_kstorage_write(const char *key, int gid, long did, void *data, int offset, int dlen);

// Read data from a storage slot
long sc_kstorage_read(const char *key, int gid, long did, void *out_data, int offset, int dlen);

// List all data IDs in a group
long sc_kstorage_list_ids(const char *key, int gid, long *ids, int ids_len);

// Remove a storage slot
long sc_kstorage_remove(const char *key, int gid, long did);
```

Reserved group IDs:

| Group ID | Constant | Purpose |
|----------|----------|---------|
| 0 | `KSTORAGE_SU_LIST_GROUP` | SU allow list |
| 1 | `KSTORAGE_EXCLUDE_LIST_GROUP` | Module exclude list |

### Superkey Management

```c
// Get the current superkey
long sc_skey_get(const char *key, char *out_key, int outlen);

// Change the superkey
long sc_skey_set(const char *key, const char *new_key);

// Enable or disable hash verification for root superkey
long sc_skey_root_enable(const char *key, bool enable);
```

## Command Code Reference

| Command | Code | Description |
|---------|------|-------------|
| `SUPERCALL_HELLO` | 0x1000 | Ping / check installation |
| `SUPERCALL_KLOG` | 0x1004 | Kernel log message |
| `SUPERCALL_BUILD_TIME` | 0x1007 | KP build timestamp |
| `SUPERCALL_KERNELPATCH_VER` | 0x1008 | KP version |
| `SUPERCALL_KERNEL_VER` | 0x1009 | Kernel version |
| `SUPERCALL_SKEY_GET` | 0x100a | Get superkey |
| `SUPERCALL_SKEY_SET` | 0x100b | Set superkey |
| `SUPERCALL_SKEY_ROOT_ENABLE` | 0x100c | Enable root hash |
| `SUPERCALL_SU` | 0x1010 | SU current thread |
| `SUPERCALL_SU_TASK` | 0x1011 | SU specific thread |
| `SUPERCALL_KPM_LOAD` | 0x1020 | Load KPM |
| `SUPERCALL_KPM_UNLOAD` | 0x1021 | Unload KPM |
| `SUPERCALL_KPM_CONTROL` | 0x1022 | Control KPM |
| `SUPERCALL_KPM_NUMS` | 0x1030 | Number of KPMs |
| `SUPERCALL_KPM_LIST` | 0x1031 | List KPM names |
| `SUPERCALL_KPM_INFO` | 0x1032 | KPM info |
| `SUPERCALL_KSTORAGE_WRITE` | 0x1041 | Write storage |
| `SUPERCALL_KSTORAGE_READ` | 0x1042 | Read storage |
| `SUPERCALL_KSTORAGE_LIST_IDS` | 0x1043 | List storage IDs |
| `SUPERCALL_KSTORAGE_REMOVE` | 0x1044 | Remove storage |
| `SUPERCALL_SU_GRANT_UID` | 0x1100 | Grant SU to UID |
| `SUPERCALL_SU_REVOKE_UID` | 0x1101 | Revoke SU from UID |
| `SUPERCALL_SU_NUMS` | 0x1102 | Count SU UIDs |
| `SUPERCALL_SU_LIST` | 0x1103 | List SU UIDs |
| `SUPERCALL_SU_PROFILE` | 0x1104 | Get UID SU profile |
| `SUPERCALL_SU_GET_ALLOW_SCTX` | 0x1105 | Get all-allow SELinux context |
| `SUPERCALL_SU_SET_ALLOW_SCTX` | 0x1106 | Set all-allow SELinux context |
| `SUPERCALL_SU_GET_PATH` | 0x1110 | Get SU binary path |
| `SUPERCALL_SU_RESET_PATH` | 0x1111 | Set SU binary path |
| `SUPERCALL_SU_GET_SAFEMODE` | 0x1112 | Check safe mode |

## Example: Check KernelPatch and Get Version

```c
#include <stdio.h>
#include "supercall.h"

int main(void)
{
    const char *key = "mysuperkey";

    if (!sc_ready(key)) {
        printf("KernelPatch not installed\n");
        return 1;
    }

    uint32_t kp_ver = sc_kp_ver(key);
    uint32_t k_ver  = sc_k_ver(key);

    printf("KernelPatch version: %d.%d.%d\n",
           (kp_ver >> 16) & 0xff,
           (kp_ver >> 8) & 0xff,
           kp_ver & 0xff);

    printf("Kernel version: %d.%d.%d\n",
           (k_ver >> 16) & 0xff,
           (k_ver >> 8) & 0xff,
           k_ver & 0xff);

    return 0;
}
```

## Example: Grant Root to Current Process

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
