ifndef TARGET_COMPILE
    $(error TARGET_COMPILE is not set)
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

CFLAGS = -std=c11 -Wall

objs := hello.O

all: kpm_hello

kpm_hello: hello.o ${objs}
	${CC} -fpic -shared -o $@ $^

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf kpm_hello
	find . -name "*.o" | xargs rm -f