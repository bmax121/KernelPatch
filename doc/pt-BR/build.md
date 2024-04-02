# Como compilar

## Compilando kpimg

Requer um compilador cruzado bare-metal. [Baixe aqui](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads).

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kernel
export ANDROID=1 # Versão do Android, incluindo suporte para o comando "su".
make
```

## Compilando kptools

O kptools pode ser executado em qualquer lugar, basta compilá-lo.

- Usando Makefile

```shell
export ANDROID=1
cd tools
make
```

- Usando CMake

```shell
cd tools
mkdir build
cd build
cmake ..
make
```

## Compilando kpatch

O kpatch é executado no espaço do usuário do sistema de destino, para que você possa construí-lo normalmente. Se estiver usando para o Android, você pode usar AndroidKernelPatch.

- Usando Makefile

```shell
cd user
make
```

- Usando CMake

```shell
cd user
mkdir build
cd build
cmake ..
make
```

- Compilar para Android

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

## Compilar Módulo KernelPatch

Exemplo:

```shell
export TARGET_COMPILE=aarch64-none-elf-
cd kpm-demo/hello
make
```
