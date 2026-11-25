# 编译说明

## 编译 kpimg

需要裸机交叉编译器
[点击此处下载](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
export ANDROID=1 # Android 版本，包含 su 命令支持
make
```

### 仅 KPM 编译

`KPM_ONLY=1` 只保留 KPM 宿主：`SUPERCALL_KPM_*` 命令、模块加载器与事件分发。
SELinux 策略快照 / 隐藏代码以及 `patch/android/userd.c` 不会参与编译，
因此 su 与 trusted-manager 相关逻辑、`/data/adb/ap/kpm` 加载，
以及启动阶段事件（`pre-exec-init`、`init first/second stage`）都不包含在内。

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
export ANDROID=1
export KPM_ONLY=1
make
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
