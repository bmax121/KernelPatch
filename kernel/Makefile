ifndef TARGET_COMPILE
    $(error TARGET_COMPILE is not set)
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld
AS = $(TARGET_COMPILE)as
OBJCOPY = $(TARGET_COMPILE)objcopy

CFLAGS += -Wall -fno-builtin -std=gnu11 -nostdinc
CFLAGS += -g

ifdef DEBUG
	CFLAGS += -DDEBUG -DMAP_DEBUG -g
endif

INCLUDE := -I. -Iinclude -Iinit/include -Ilinux -Ilinux/include -Ilinux/arch/arm64/include

BASE_SRCS += base/hook.c 
BASE_SRCS += base/map.c 
BASE_SRCS += base/hmem.c 
BASE_SRCS += base/setup.c 
BASE_SRCS += base/setup1.S
BASE_SRCS += base/start.c 
BASE_SRCS += base/predata.c 

BASE_SRCS += $(wildcard module/*.c)
BASE_SRCS += $(wildcard accctl/*.c)

BASE_SRCS += $(wildcard init/*.c)
BASE_SRCS += $(wildcard init/ext/*.c)
BASE_SRCS += $(wildcard init/ksyms/*.c)
BASE_SRCS += $(wildcard init/struct/*.c)


SRCS += $(BASE_SRCS)
SRCS += $(LINUX_SRCS)

OBJS := $(SRCS:.c=.o)
OBJS := $(OBJS:.S=.o)

all: kpimg

kpimg: kpimg.elf
	${OBJCOPY} -O binary -S $^ $@

kpimg.elf: ${OBJS}
	${LD} -nostdlib -static -no-pie -Tkpimg.lds -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE) -c -O2 -o $@ $<

%.o: %.S
	${CC} $(CFLAGS) $(INCLUDE) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.elf
	rm -rf kpimg
	find . -name *.o | xargs rm -f