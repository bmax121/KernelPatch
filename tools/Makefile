
CFLAGS = -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter
# CFLAGS += -g

ifdef ANDROID
	CFLAGS += -DANDROID
endif

objs := image.o kallsym.o kptools.o order.o

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