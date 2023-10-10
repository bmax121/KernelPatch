
CFLAGS = -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter

ifdef ANDROID
	CFLAGS += -DANDROID
endif

objs := libkp.o 

all: hdr libkp.a kpatch

kpatch: main.o ${objs}
	${CC} -o $@ $^

libkp.a: ${objs}
	${AR} rcs $@ $^

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

hdr:
	cp -r ../kernel/patch/include/uapi .
	cp ../kernel/version .

.PHONY: clean
clean:
	rm -rf build
	rm -rf uapi
	rm -f kpatch
	rm -f libkp.a 
	find . -name "*.o" | xargs rm -f