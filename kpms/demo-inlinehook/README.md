# kpm-inline-hook-demo (Revived)

A KernelPatch Module (KPM) example demonstrating inline hooking capabilities on ARM64. This project provides a simple demo where an internal function `add` is hooked using `hook_wrap2` to log arguments and modify the return value.

## Overview

This repository contains a demonstration of:
- **KernelPatch Module (KPM)**: Implementing a modular kernel patch.
- **Inline Hooking**: Using `hook_wrap2` for low-level function hooking.
- **Logic Modification**: Intercepting function arguments and overriding return values in `before` and `after` hooks.
- **KPM Lifecycle**: Using `KPM_INIT`, `KPM_EXIT`, and `KPM_CTL0` macros.
- **Dynamic Control**: A control interface allowing manual hooking/unhooking from userspace.

## Stack & Requirements

- **Language**: C
- **Framework**: [KernelPatch](https://github.com/bmax121/KernelPatch)
- **Target Architecture**: ARM64 (aarch64)
- **Toolchain**: `aarch64-linux-gnu-gcc` cross-compiler
- **Build System**: GNU Make, .NET SDK (for C# package)

## Environment Variables

The build process requires the following environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `TARGET_COMPILE` | Prefix for the cross-compiler toolchain (e.g., `aarch64-linux-gnu-`). **Required**. | None |
| `KP_DIR` | Path to the KernelPatch root directory. | `../..` |

## Setup & Build

### 1. Clone & Prepare
Ensure you have the KernelPatch repository available, as this module depends on its headers.

### 2. Build the Module
Run `make` while providing the required variables:

```bash
make TARGET_COMPILE=aarch64-linux-gnu- KP_DIR=/path/to/KernelPatch
```

This will produce `inlinehook.kpm`, which is the loadable module.

### 3. Build the C# Package (Optional)
To build the C# metadata wrapper:

```bash
dotnet build demo-inlinehook.csproj
```

### 4. Cleanup
To remove build artifacts:

```bash
make clean
```

## Project Structure

```text
.
├── Makefile                # Build configuration
├── README.md               # Project documentation
├── inlinehook.c            # Main KPM source code
├── Package.cs              # C# Metadata Package
├── demo-inlinehook.csproj  # C# Project File
└── Folder.DotSettings.user # IDE settings (Rider/ReSharper)
```

- `inlinehook.c`: Contains the module metadata, the `add` function to be hooked, hook callbacks (`before_add`, `after_add`), and lifecycle handlers.
- `Makefile`: Configures the compiler, include paths (pointing to `KP_DIR`), and build targets.
- `Package.cs`: C# metadata wrapper for the module (using `Microsoft.Win32` namespace).
- `demo-inlinehook.csproj`: .NET project file for the C# package.

## How it Works

### Entry Points
- **Initialization (`KPM_INIT`)**: `inline_hook_demo_init`
  - Logs the initial call to `add(20, 10)` (returns 30).
  - Installs the hook using `hook_wrap2`.
  - Logs a subsequent call to `add(20, 10)` (returns 100 due to hook).
- **Exit (`KPM_EXIT`)**: `inline_hook_demo_exit`
  - Uninstalls the hook.
  - Verifies `add` returns to original behavior.
- **Control (`KPM_CTL0`)**: `inline_hook_control0`
  - Accessible from userspace to toggle the hook.

### Hook Logic
1. **`before_add`**: Invoked before the original `add` function. It accesses arguments via `hook_fargs2_t *args` and logs them.
2. **`after_add`**: Invoked after the original `add` function. It modifies `args->ret` to `100`, overriding the actual sum.

## Testing & Usage

After loading the module into a KernelPatch-enabled environment:
- Monitor kernel logs (`dmesg`) to see the initialization and hook logs.
- Use the KPM control interface (usually via `/dev/kp_control` or similar, depending on KernelPatch setup) to send commands:
  - `echo "unhook" > /proc/kp_msg` (Example: path may vary)
  - `echo "hook" > /proc/kp_msg`

## License

- **License**: GPL v2 (as specified in `inlinehook.c`)
- **Copyright**: (C) 2023-2026 bmax121
