cmake_minimum_required(VERSION 3.5)
project("kpatch")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")

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