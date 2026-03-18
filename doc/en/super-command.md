# Super Command

The super command is implemented by hooking the `truncate` syscall. When `/system/bin/truncate` is executed with a valid superkey (or `su`) as the first argument, KernelPatch intercepts the call and executes the requested command instead.

## General Usage

```
truncate <superkey|su> [-u UID] [-Z SCONTEXT] [COMMAND [...]]
```

The first argument is authentication:
- **superkey** — the configured superkey grants full access to all commands.
- **su** — the string `"su"` can be used if the calling process's UID has been granted SU access; only `sumgr` and non-superkey commands are available.

If no command is given, an interactive shell is launched with the specified credentials.

## Options

These options appear before the command and modify the credentials used for execution:

| Option | Description |
|--------|-------------|
| `-u <UID>` | Switch to the specified UID before executing the command |
| `-Z <SCONTEXT>` | Switch to the specified SELinux security context |

## Commands

### `help`

Print the full usage message.

```
truncate <superkey> help
```

### `version`

Print the kernel version and KernelPatch version as hex values.

```
truncate <superkey> version
```

Output format: `<kernel_ver_hex>,<kp_ver_hex>`
Example: `50a0a,a06` means kernel 5.10.10, KernelPatch 0.10.6.

### `buildtime`

Print the KernelPatch build timestamp.

```
truncate <superkey> buildtime
```

### `-c <COMMAND> [...]`

Pass a command string to the default shell (`/system/bin/sh`).

```
truncate <superkey> -c "id"
truncate <superkey> -u 0 -Z u:r:su:s0 -c "ls /data"
```

### `exec <PATH> [...]`

Execute a program directly by full path.

```
truncate <superkey> exec /data/local/tmp/my_program arg1 arg2
```

### `sumgr` — SU Permission Manager

Manage which UIDs are allowed to use SU.

```
truncate <superkey|su> sumgr <subcommand> [...]
```

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `grant` | `<UID> [TO_UID [SCONTEXT]]` | Grant SU permission to UID, switching to TO_UID with SCONTEXT |
| `revoke` | `<UID>` | Revoke SU permission from UID |
| `num` | | Get the number of UIDs with SU permission |
| `list` | | List all UIDs with SU permission |
| `profile` | `<UID>` | Get the SU profile (to_uid, scontext) for a UID |
| `path` | `[PATH]` | Get or set the su binary path (length must be 2–127) |
| `sctx` | `[SCONTEXT]` | Get or set the all-allow SELinux context |
| `exclude` | `<UID> [1\|0]` | Get or set module exclude policy for a UID (Android only) |
| `exclude_list` | | List all excluded UIDs (Android only) |

Examples:

```shell
# Grant root to UID 2000, switch to uid 0, default scontext
truncate <superkey> sumgr grant 2000

# Grant to UID 2000, switch to uid 0 with a custom scontext
truncate <superkey> sumgr grant 2000 0 u:r:su:s0

# Revoke
truncate <superkey> sumgr revoke 2000

# Show profile of UID 2000
truncate <superkey> sumgr profile 2000

# Change the su binary path
truncate <superkey> sumgr path /data/local/tmp/mysu

# Set all-allow SELinux context
truncate <superkey> sumgr sctx u:r:su:s0
```

### `module` — KPM Module Manager

Requires superkey authentication.

```
truncate <superkey> module <subcommand> [...]
```

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `load` | `<KPM_PATH> [KPM_ARGS]` | Load a KPM from KPM_PATH, passing KPM_ARGS to its init |
| `unload` | `<KPM_NAME>` | Unload the module named KPM_NAME |
| `ctl0` | `<KPM_NAME> <CTL_ARGS>` | Send a control string to the module |
| `num` | | Get the number of currently loaded modules |
| `list` | | List names of all loaded modules |
| `info` | `<KPM_NAME>` | Get detailed info about a module |

Examples:

```shell
truncate <superkey> module load /data/local/tmp/my.kpm "init args"
truncate <superkey> module ctl0 my-module "ping"
truncate <superkey> module info my-module
truncate <superkey> module unload my-module
truncate <superkey> module list
```

### `key` — Superkey Manager

Requires superkey authentication.

```
truncate <superkey> key <subcommand> [...]
```

| Subcommand | Arguments | Description |
|------------|-----------|-------------|
| `get` | | Print the current superkey |
| `set` | `<NEW_KEY>` | Change the superkey to NEW_KEY |
| `hash` | `enable\|disable` | Enable or disable hash verification for the root superkey |

Examples:

```shell
truncate <superkey> key get
truncate <superkey> key set mynewsecretkey
truncate <superkey> key hash enable
```

### `event`

Report a user event to KernelPatch.

```
truncate <superkey|su> event <EVENT> [DATA]
```

### `bootlog`

Print the KernelPatch boot log.

```
truncate <superkey> bootlog
```
