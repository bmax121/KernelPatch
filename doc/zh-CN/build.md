# 如何构建

## 构建 kpimg

需要本机交叉编译器  
[这里下载](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
export ANDROID=1 # 安卓版本, 包括对“su”命令的支持
make
```

## 构建 kptools

kptools 可以在任何地方运行, 只要编译它.  

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

## 使用 kpatch

kpatch 运行在目标系统的用户空间, 所以你可以构建它像平常一样.  
如果您将其用于Android, 你可以使用 AndroidKernelPatch.

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

- 为Android编译

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

## 构建 KernelPatch 模块

例子:

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kpm-demo/hello
make
```
