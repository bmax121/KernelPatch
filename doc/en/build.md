# How to Build

## Build kpimg

kpimg runs in the kernel space of the target system and may require a cross-compiler.  

So far, I have only been successful using arm-gnu-toolchain-11.3.rel1-darwin-x86_64-aarch64-none-elf on macOS (x86_64). (TODO)

[Download the Compiler](https://developer.arm.com/-/media/Files/downloads/gnu/11.3.rel1/binrel/arm-gnu-toolchain-11.3.rel1-darwin-x86_64-aarch64-none-elf.tar.xz?rev=51c39c753f8c4a54875b7c5dccfb84ef&hash=D8A89553D9AD6573EA67E64A4B43E895B7F7680E)

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
