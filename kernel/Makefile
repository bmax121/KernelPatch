ifndef TARGET_COMPILE
    $(error TARGET_COMPILE is not set)
endif

TARGET=kpimg

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld
AS = $(TARGET_COMPILE)as
OBJCOPY = $(TARGET_COMPILE)objcopy

CFLAGS += -Wall -fno-builtin -std=gnu11 -nostdinc
CFLAGS += -g

ifdef DEBUG
	CFLAGS += -DDEBUG -DMAP_DEBUG -g
endif

ifdef ANDROID
	CFLAGS += -DANDROID
endif

INCLUDE := -I. -Iinclude -Ipatch/include -Ilinux -Ilinux/include -Ilinux/arch/arm64/include -Ilinux/tools/arch/arm64/include

BASE_SRCS += base/setup.c 
BASE_SRCS += base/setup1.S
BASE_SRCS += base/start.c 
BASE_SRCS += base/map.c 
BASE_SRCS += base/hook.c 
BASE_SRCS += base/hmem.c 
BASE_SRCS += base/predata.c 
BASE_SRCS += base/symbol.c 

BASE_SRCS += $(wildcard minc/*.c)

BASE_SRCS += $(wildcard module/*.c)

BASE_SRCS += $(wildcard patch/*.c)
BASE_SRCS += $(wildcard patch/accctl/*.c)
BASE_SRCS += $(wildcard patch/extend/*.c)
BASE_SRCS += $(wildcard patch/ksyms/*.c)
BASE_SRCS += $(wildcard patch/struct/*.c)
BASE_SRCS += $(wildcard patch/debug/*.c)

ifdef ANDROID
	BASE_SRCS += $(wildcard patch/android/*.c)
endif

SRCS += $(BASE_SRCS)
SRCS += $(LINUX_SRCS)

OBJS := $(SRCS:.c=.o)
OBJS := $(OBJS:.S=.o)

all: hdr ${TARGET}

${TARGET}: ${TARGET}.elf
	${OBJCOPY} -O binary -S $^ $@

${TARGET}.elf: ${OBJS}
	${LD} -nostdlib -static -no-pie -Tkpimg.lds -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE) -c -O2 -o $@ $<

%.o: %.S
	${CC} $(CFLAGS) $(INCLUDE) -c -o $@ $<

hdr:
	cp -r patch/include/uapi ../user
	cp version ../user
	cp base/preset.h ../tools

.PHONY: clean
clean:
	rm -rf *.elf
	rm -rf kpimg
	find . -name *.o | xargs rm -f