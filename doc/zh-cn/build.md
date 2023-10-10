# 如何编译

## 编译 kpimg

需要使用裸机交叉编译器  
[下载编译器](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
# export ANDROID=1 # 适用于 Android 的版本，包含 su 命令支持
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
cd tools
mkdir build
cd build
cmake ..
make
```

## 编译 kpatch

kpatch 运行在目标系统的用户空间，像往常一样构建就好了。  

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
