# 如何编译

## 编译 kpimg

kpimg 运行在目标系统的内核空间  
目前我只在 macOS(x86_64) 上使用 arm-gnu-toolchain-11.3.rel1-darwin-x86_64-aarch64-none-elf 成功过。(TODO)

[下载编译器](https://developer.arm.com/-/media/Files/downloads/gnu/11.3.rel1/binrel/arm-gnu-toolchain-11.3.rel1-darwin-x86_64-aarch64-none-elf.tar.xz?rev=51c39c753f8c4a54875b7c5dccfb84ef&hash=D8A89553D9AD6573EA67E64A4B43E895B7F7680E)


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
