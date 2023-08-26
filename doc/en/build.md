# How to Build

## Build kpimg

Need to use a bare-metal cross-compiler.  
[Download](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
make
```

## Build kptools

kptools can run anywhere, just compile it.  
If you haven't compiled kpimg, you need to copy [/kernel/base/preset.h](/kernel/base/preset.h) to the `tool` directory.  

- Using Makefile

```shell
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

If you haven't compiled kpimg, you need to copy [/kernel/init/include/uapi](/kernel/init/include/uapi) to the `user` directory.  

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
