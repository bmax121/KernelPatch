# export ANDROID_SDK=/path/to/sdk
export ANDROID_NDK=$ANDROID_SDK/ndk/25.2.9519653
export ANDROID_CMAKE_BIN=$ANDROID_SDK/cmake/3.22.1/bin
export ANDROID_ABI=arm64-v8a
export ANDROID_PLATFORM=android-33

CMAKE=$ANDROID_CMAKE_BIN/cmake

$CMAKE -S . -B build/android -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake -DANDROID_ABI=$ANDROID_ABI -DANDROID_PLATFORM=$ANDROID_PLATFORM

$CMAKE --build ./build/android