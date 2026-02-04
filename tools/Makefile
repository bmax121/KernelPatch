CFLAGS = -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter

CFLAGS += -I. -I./lib -DBZ_NO_STDIO -DXZ_DEC_ANY_CHECK
LDFLAGS = -lz

ifdef DEBUG
    CFLAGS += -DDEBUG -g
endif

OBJS := image.o kallsym.o kptools.o order.o insn.o patch.o symbol.o kpm.o common.o bootimg.o sha256.o

LIB_SRCS := $(wildcard lib/*.c) $(wildcard lib/*/*.c)
LIB_OBJS := $(LIB_SRCS:.c=.o)


ALL_OBJS := $(OBJS) $(LIB_OBJS)

.PHONY: all
all: kptools

kptools: $(ALL_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)


%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf kptools
	find . -name "*.o" | xargs rm -f
	@echo "Clean done."