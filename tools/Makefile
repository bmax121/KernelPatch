
ifeq ($(shell uname), Linux)
    PLATFORM_SUFFIX = _linux
else ifeq ($(shell uname), Darwin)
    PLATFORM_SUFFIX = _mac
else ifeq ($(shell uname), Windows_NT)
    PLATFORM_SUFFIX = _win
else
    PLATFORM_SUFFIX = _unknown
endif

CFLAGS = -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter

objs := image.o kallsym.o kptools.o order.o

kptools: ${objs}
	${CC} -o $@ $^

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf kptools
	find . -name "*.o" | xargs rm -f