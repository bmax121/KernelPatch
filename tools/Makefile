
CFLAGS = -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter
# CFLAGS += -g

objs := image.o kallsym.o kptools.o order.o

all: hdr kptools

kptools: ${objs}
	${CC} -o $@ $^

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

hdr:
	cp ../kernel/base/preset.h .

.PHONY: clean
clean:
	rm -rf preset.h
	rm -rf kptools
	find . -name "*.o" | xargs rm -f