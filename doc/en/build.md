# How to Build

## Build kpimg

Require a bare-metal cross compiler  
[Download here](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
export ANDROID=1 # Android version, including support for the 'su' command
make
```

### KPM-only build

`KPM_ONLY=1` keeps only the KPM host: the `SUPERCALL_KPM_*` commands, the
module loader and the event dispatch. It leaves out the SELinux policy snapshot
/ hide code and `patch/android/userd.c`, so the su and trusted-manager
machinery, `/data/adb/ap/kpm` loading and the boot-stage events
(`pre-exec-init`, `init first/second stage`) are not built.

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
export ANDROID=1
export KPM_ONLY=1
make
```

## Build kptools

kptools can run anywhere, just compile it.  

- Using Makefile

```shell
export ANDROID=1
cd tools
make
```

- Using CMake

```shell
cd tools
mkdir build
cd build
cmake ..
make
```

## Building kpatch

kpatch runs in the user space of the target system, so you can build it as usual.  
If you are using it for Android, you can use AndroidKernelPatch.

- Using Makefile

```shell
cd user
make
```

- Using CMake

```shell
cd user
mkdir build
cd build
cmake ..
make
```

- Compile for Android

```shell
export ANDROID_NDK=/path/to/ndk
export ANDROID=1
cd user
mkdir -p build/android && cd build/android
cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DANDROID_PLATFORM=android-33 \
    -DANDROID_ABI=arm64-v8a ../..
cmake --build .
```

## Build KernelPatch Module

example:

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kpms/demo-hello
make
```
