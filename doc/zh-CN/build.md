# 编译说明

## 编译 kpimg

需要裸机交叉编译器
[点击此处下载](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
export ANDROID=1 # Android 版本，包含 su 命令支持
make

# 或者在不包含内置 root 的情况下编译
make NO_ROOT=1
# 或 Android 版本不包含内置 root
make ANDROID=1 NO_ROOT=1

# Manager 可选标志：
# 当 NO_ROOT=1 时，官方 Manager 的 rename hook 和 APK 扫描默认处于禁用状态。
# 在 NO_ROOT 构建中启用官方 Manager 包监控：
make ANDROID=1 NO_ROOT=1 OFFICIAL_MANAGER=1
# 在标准 root 构建中禁用官方 Manager rename hook：
make ANDROID=1 NO_MANAGER=1
```

## 编译 kptools

kptools 可在任意平台编译。

- 使用 Makefile

```shell
export ANDROID=1
cd tools
make
```

- 使用 CMake

```shell
cd tools
mkdir build
cd build
cmake ..
make
```

## 编译 kpatch

kpatch 运行在目标系统的用户空间，按常规方式编译即可。
如果用于 Android，可以使用 AndroidKernelPatch。

- 使用 Makefile

```shell
cd user
make
```

- 使用 CMake

```shell
cd user
mkdir build
cd build
cmake ..
make
```

- 编译 Android 版本

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

## 编译 KernelPatch 模块

示例：

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kpms/demo-hello
make
```
