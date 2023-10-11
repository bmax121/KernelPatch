
CFLAGS = -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter

ifdef ANDROID
	CFLAGS += -DANDROID
endif

objs := kpatch.o 

all: hdr libkpatch.a kpatch

kpatch: main.o ${objs}
	${CC} -o $@ $^

libkpatch.a: ${objs}
	${AR} rcs $@ $^

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf build
	rm -rf uapi
	rm -f kpatch
	rm -f libkpatch.a 
	find . -name "*.o" | xargs rm -f