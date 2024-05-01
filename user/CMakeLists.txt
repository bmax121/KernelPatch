cmake_minimum_required(VERSION 3.5)
project("kpatch")

include_directories(${CMAKE_CURRENT_BINARY_DIR})

if(ANDROID)
set(OPT_FLAGS "-ffunction-sections -fdata-sections -fvisibility=hidden -fvisibility-inlines-hidden -mllvm -polly -O3 -flto")
else()
set(OPT_FLAGS "-O3")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ${OPT_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 ${OPT_FLAGS}")

if(ANDROID)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DANDROID")    
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DANDROID")    
endif()

set(SRCS 
    kpatch.c
    kpm.c
    su.c
)

if(ANDROID)
    file(GLOB ANDROID_SRCS "android/*.c")
    list(APPEND SRCS ${ANDROID_SRCS})
endif()

add_library(kp STATIC ${SRCS})
add_executable(kpatch ${SRCS} main.c)
if(ANDROID)
target_link_options(kp PRIVATE "-Wl,--build-id=none" "-Wl,-icf=safe,--lto-O3" "-Wl,-s,-x,--gc-sections" "-Wl,--no-undefined")
target_link_options(kpatch PRIVATE "-Wl,--build-id=none" "-Wl,-icf=safe,--lto-O3" "-Wl,-s,-x,--gc-sections" "-Wl,--no-undefined")
endif()

if(ANDROID)
add_library(
    apjni 
    SHARED
    android/apjni.cpp
)
target_link_libraries(apjni log)
target_link_options(apjni PRIVATE "-Wl,--build-id=none" "-Wl,-icf=safe,--lto-O3" "-Wl,-s,-x,--gc-sections" "-Wl,--no-undefined")
endif()