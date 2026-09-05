# How to Build

## Build kpimg

Require a bare-metal cross compiler  
[Download here](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
export ANDROID=1 # Android version, including support for the 'su' command
make

# Or build without built-in root
make NO_ROOT=1
# Or Android version without built-in root
make ANDROID=1 NO_ROOT=1

# Optional manager flags:
# When NO_ROOT=1, official manager rename hooks and APK scans are disabled by default.
# To enable official manager package monitoring in NO_ROOT builds:
make ANDROID=1 NO_ROOT=1 OFFICIAL_MANAGER=1
# To disable official manager rename hooks in a standard root build:
make ANDROID=1 NO_MANAGER=1
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
