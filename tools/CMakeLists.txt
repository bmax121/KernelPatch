cmake_minimum_required(VERSION 3.5)

project (kptools)

set(SOURCES
	image.c
	kallsym.c
	kptools.c
	order.c
)

add_executable(
	kptools 
	${SOURCES}
)