cmake_minimum_required(VERSION 3.5)
project (kptools)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(SOURCES
	image.c
	kallsym.c
	kptools.c
	order.c
	insn.c
	patch.c
	symbol.c
)

add_executable(
	kptools 
	${SOURCES}
)