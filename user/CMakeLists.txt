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
        )

add_library(
        libkpatch
        STATIC
        ${SRCS}
        )

add_executable(
        kpatch
        ${SRCS}
        main.c
        )