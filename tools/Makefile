
CFLAGS = -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter

ifdef DEBUG
	CFLAGS += -DDEBUG -g
endif

objs := image.o kallsym.o kptools.o order.o insn.o patch.o symbol.o kpm.o common.o
objs += sha256.o

.PHONY: all
all: kptools

.PHONY: kptools
kptools: ${objs}
	${CC} -o $@ $^

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf preset.h
	rm -rf kptools
	find . -name "*.o" | xargs rm -f
