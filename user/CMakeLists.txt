cmake_minimum_required(VERSION 3.5)
project("kpatch")

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")

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
    list(APPEND SRCS "sumgr.c")
    file(GLOB ANDROID_SRCS "android/*.c")
    list(APPEND SRCS ${ANDROID_SRCS})
endif()


add_library(kp STATIC ${SRCS})

add_executable(kpatch ${SRCS} main.c)

if(ANDROID)
add_library(
    apjni 
    SHARED
    ${SRCS}
    apjni.cpp
)
find_library(lib-log log)
target_link_libraries(apjni ${lib-log})
endif()