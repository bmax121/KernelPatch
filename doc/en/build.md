# How to Build

## Build kpimg

kpimg runs in the kernel space of the target system and may require a cross-compiler.

In some cases, the compiler may generate a .got table, which is not currently supported (todo).
It has only been tested on MacOS (Intel CPU) with aarch64-none-elf-.

[Download the Compiler](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
make
```

## Build kptools

kptools can run anywhere, just compile it.

- Using Makefile

```shell
cd tools
make
```

- Using CMake

```shell
mkdir build
cd build
cmake ..
make
```

## Building kpatch

kpatch runs in the user space of the target system, so you can build it as usual, for example, using NDK on Android.

- Using Makefile

```shell
cd tools
make
```

- Using CMake

```shell
mkdir build
cd build
cmake ..
make
```
