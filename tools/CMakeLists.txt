cmake_minimum_required(VERSION 3.5)
project (kptools)

file(GLOB_RECURSE LIB_SOURCES "lib/*.c")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_definitions(-DZSTD_DISABLE_ASM)
add_definitions(-DXZ_DEC_ANY_CHECK)
set(SOURCES
    image.c
    kallsym.c
    kptools.c
    order.c
    insn.c
    patch.c
    symbol.c
    kpm.c
    common.c
    sha256.c
    bootimg.c
)

add_executable(
    kptools 
    ${SOURCES}
    ${LIB_SOURCES}
)

file(GLOB_RECURSE ALL_HEADERS "lib/*.h")
set(LIB_INCLUDE_DIRS "")
foreach(_header_file ${ALL_HEADERS})
    get_filename_component(_dir ${_header_file} DIRECTORY)
    list(APPEND LIB_INCLUDE_DIRS ${_dir})
endforeach()
list(REMOVE_DUPLICATES LIB_INCLUDE_DIRS)

target_include_directories(kptools PRIVATE ${LIB_INCLUDE_DIRS})
target_compile_definitions(kptools PRIVATE BZ_NO_STDIO)
find_package(ZLIB REQUIRED)
target_include_directories(kptools PRIVATE ${ZLIB_INCLUDE_DIRS})

target_link_libraries(kptools PRIVATE ${ZLIB_LIBRARIES})