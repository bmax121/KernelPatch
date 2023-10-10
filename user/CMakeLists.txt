cmake_minimum_required(VERSION 3.5)
project("kpatch")

# hdr
file(COPY "../kernel/patch/include/uapi" DESTINATION ".")
file(COPY "../kernel/version" DESTINATION ".")

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")

if(ANDROID)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DANDROID")    
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DANDROID")    
endif()

set(SRCS
        libkp.c
        )

add_library(
        kp
        STATIC
        ${SRCS}
        )

add_executable(
        kpatch
        ${SRCS}
        main.c
        )