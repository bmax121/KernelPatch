# 如何编译

## 编译 kpimg

kpimg 运行在目标系统的内核空间  
目前只在 macOS(x86_64) 上使用裸机编译器测试过

[下载编译器](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
make
```

## 编译 kptools

kptools 可以运行在任何地方，编译就好了

- 使用 Makefile

```shell
cd tools
make
```

- 使用 CMake

```shell
mkdir build
cd build
cmake ..
make
```

## 编译 kpatch

kpatch 运行在目标系统的用户空间，像往常一样构建就好了，例如在 Android 上使用 ndk

- 使用 Makefile

```shell
cd tools
make
```

- 使用 CMake

```shell
mkdir build
cd build
cmake ..
make
```
