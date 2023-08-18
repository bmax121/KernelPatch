
CFLAGS = -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter

objs := libkp.o 

all: kpatch libkp.a

kpatch: main.o ${objs}
	${CC} -o $@ $^

libkp.a: ${objs}
	${AR} rcs $@ $^

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf uapi/*
	rm -rf kpatch
	rm -rf libkp.a 
	find . -name "*.o" | xargs rm -f