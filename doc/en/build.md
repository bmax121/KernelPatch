# How to Build

## Build kpimg

kpimg runs in the kernel space of the target system. 
You may need a bare-metal cross-compiler, such as aarch64-none-elf, for compilation.

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
