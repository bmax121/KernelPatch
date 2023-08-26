# 如何编译

## 编译 kpimg

需要使用裸机交叉编译器  
[下载编译器](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
make
```

## 编译 kptools

kptools 可以运行在任何地方，编译就好了  

假如你并未编译 kpimg，你需要把 [/kernel/base/preset.h](/kernel/base/preset.h) 复制到 `tool` 目录下

- 使用 Makefile

```shell
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

kpatch 运行在目标系统的用户空间，像往常一样构建就好了。  
如果你是用于 Android，你可以使用 AndroidKernelPatch。  

如果你并未编译 kpimg，你需要把 [/kernel/init/include/uapi](/kernel/init/include/uapi) 复制到 `user` 目录下

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
