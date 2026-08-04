# KernelPatch LKM (DDK-built .ko)

KernelPatch as a loadable kernel module, built with Android's Driver
Development Kit (DDK), for kernels where loading a `.ko` is possible. This is
an alternative delivery path to the image-patched `kpimg` — it does not touch
the kernel image or repack `boot.img`.

## Status (framework)

This is a **framework/skeleton**. It currently:

- loads via `insmod` and logs a banner
- resolves non-exported symbols at runtime (`sys_call_table`, `init_mm`, ...)
- scans `/data/app` for the trusted APatch manager APK (certificate-verified
  via the v2 signing block) and records its uid from `packages.list`
- hooks syscall 45 (`truncate`) as the KP supercall channel
- authenticates supercalls by **manager uid** (no superkey needed)
- answers `SUPERCALL_HELLO`, `KERNELPATCH_VER`, `KERNEL_VER`
- grants root on `SUPERCALL_SU` via `prepare_kernel_cred(NULL)` +
  `commit_creds()`

Not implemented yet (TODO): `SUPERCALL_SU_TASK`, kpm loader, kstorage,
allowlist persistence, SELinux scontext translabel (`commit_su` in
`kernel/patch/common/accctl.c`), inline-hook infra, x86_64.

## Prerequisites (device)

- kernel with `CONFIG_MODULES=y` (GKI 5.10 has it)
- module loading not forced-signed: `CONFIG_MODULE_SIG_FORCE=n`, or a kernel
  that accepts unsigned modules (typical for rootable/test builds). If the
  kernel enforces signatures, sign the `.ko` or disable the check.

## Build

### CI

Push to the `lkm/**` path (or run `workflow_dispatch`) — `.github/workflows/
build-lkm.yml` builds `android12-5.10` and `android13-5.10` in the
`ghcr.io/ylarod/ddk-min` container and uploads the `.ko` artifact.

### Locally

With the [`ddk`](https://github.com/5ec1cff/ddk) toolchain configured:

```sh
ddk build android12-5.10 ODIR="$(pwd)/out" -e CONFIG_KP_LKM=m
```

Or inside the DDK container / a configured kernel tree (`KDIR` set):

```sh
cd lkm
CONFIG_KP_LKM=m CC=clang make
```

## Test (root via APatch)

1. Push and load the module:

   ```sh
   adb push android12-5.10_kernelpatch.ko /data/local/tmp/
   adb shell
   su 0 insmod /data/local/tmp/android12-5.10_kernelpatch.ko
   dmesg | grep kernelpatch-lkm   # banner + "LKM ready"
   ```

2. Install the APatch manager app (`me.bmax.apatch`) and log in as the
   manager. The module's scan runs in a workqueue right after load and should
   find the manager APK; check:

   ```sh
   dmesg | grep -i "trusted manager"
   # "trusted manager crowned: me.bmax.apatch uid=10xxx"
   ```

3. Request root from the manager UI, or from a shell as the manager app:

   ```sh
   # inside the manager app's shell / via the APatch UI "root" action
   ```

   `SUPERCALL_SU` grants the caller root. If the manager is not detected,
   re-scan with:

   ```sh
   su 0 rmmod kernelpatch && su 0 insmod /data/local/tmp/android12-5.10_kernelpatch.ko
   ```

## Layout

```
lkm/
  Kbuild / Makefile / Kconfig    # DDK module build
  include/                       # kp_lkm.h, ktypes.h shim (for scdefs.h), sha256.h
  core/init.c                    # module entry, stack_chk_guard workaround
  infra/                         # symbol_resolver, patch_memory, syscall_table, sha256
  manager/                       # apk_sign (cert verify), manager (scan + uid + auth)
  supercall/                     # supercall (hooked entry), dispatch, su
```
