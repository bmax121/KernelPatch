
CFLAGS = -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter

ifdef ANDROID
	CFLAGS += -DANDROID
endif

SRC += kpatch.c
SRC += kpm.c
SRC += su.c

ifdef ANDROID
SRCS += $(wildcard android/*.c)
endif

OBJS := $(SRCS:.c=.o)

all: kpatch.a kpatch

kpatch: main.o ${OBJS}
	${CC} -o $@ $^

kpatch.a: ${OBJS}
	${AR} rcs $@ $^

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf build
	rm -rf uapi
	rm -f kpatch
	rm -f *.a 
	find . -name "*.o" | xargs rm -f