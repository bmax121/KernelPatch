ARM_BUILD_GOALS := all kpimg kpimg.elf
ifeq ($(strip $(MAKECMDGOALS)),)
    NEED_ARM_BUILD := 1
else ifneq ($(filter $(ARM_BUILD_GOALS),$(MAKECMDGOALS)),)
    NEED_ARM_BUILD := 1
endif

ifdef NEED_ARM_BUILD
    ifndef TARGET_COMPILE
        $(error TARGET_COMPILE not set)
    endif
endif

TARGET=kpimg
X86_TARGET=kpimg-x86

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld
AS = $(TARGET_COMPILE)as
OBJCOPY = $(TARGET_COMPILE)objcopy

X86_CC ?= gcc
X86_LD ?= ld
X86_OBJCOPY ?= objcopy

CFLAGS += -Wall -fno-builtin -std=gnu11 -nostdinc -mgeneral-regs-only -ffixed-x18
CFLAGS += -g

# kpimg-x86 links at 0 and runs from wherever it was injected, and the linker
# script keeps no relocations, so every reference has to be RIP-relative.
# -fno-pic would emit R_X86_64_32 for a plain &symbol, baking in the link-time
# address; -fpic with hidden visibility gives a lea (%rip) and an empty GOT.
X86_CFLAGS := -Wall -Wextra -fno-builtin -fpic -fvisibility=hidden -fno-stack-protector
X86_CFLAGS += -fcf-protection=none -m64 -mno-red-zone
X86_CFLAGS += -mgeneral-regs-only -std=gnu11 -nostdinc -Os
X86_CFLAGS += -DCONFIG_X86_64 -DDEBUG

ifdef DEBUG
	CFLAGS += -DDEBUG -DMAP_DEBUG -g
	X86_CFLAGS += -DDEBUG -g
endif

ifdef ANDROID
	CFLAGS += -DANDROID
	X86_CFLAGS += -DANDROID
endif

INCLUDE := -I. -Iinclude -Ipatch/include -Ilinux -Ilinux/include -Ilinux/arch/arm64/include -Ilinux/tools/arch/arm64/include

X86_INCLUDE := -I. -Iinclude -Ipatch/include -Ilinux/include -Ilinux/include/uapi/asm-generic -Ilinux/tools/arch/arm64/include

BASE_SRCS += base/setup.c
BASE_SRCS += base/setup1.S
BASE_SRCS += base/cache.S
BASE_SRCS += base/tlsf.c
BASE_SRCS += base/start.c 
BASE_SRCS += base/map.c 
BASE_SRCS += base/map1.S 
BASE_SRCS += base/hook.c 
BASE_SRCS += base/fphook.c 
BASE_SRCS += base/hotpatch.c 
BASE_SRCS += base/hmem.c 
BASE_SRCS += base/predata.c 
BASE_SRCS += base/puff/puff.c
BASE_SRCS += base/puff/setjmp_aarch64.S
BASE_SRCS += base/symbol.c 
BASE_SRCS += base/baselib.c 
BASE_SRCS += base/sha256.c 

BASE_SRCS += $(wildcard patch/*.c)
BASE_SRCS += $(wildcard patch/common/*.c)
BASE_SRCS += $(wildcard patch/module/*.c)
BASE_SRCS += $(wildcard patch/ksyms/*.c)

ifdef ANDROID
	BASE_SRCS += $(wildcard patch/android/*.c)
endif

SRCS += $(BASE_SRCS)
SRCS += $(LINUX_SRCS)

OBJS := $(SRCS:.c=.o)
OBJS := $(OBJS:.S=.o)

X86_OBJS := x86/setup.x86.o x86/entry.x86.o x86/x86_start.x86.o

# Shared C sources compiled with the x86 toolchain
# hmem.c depends on hook.h (ARM64 — skip for now)


all: hdr ${TARGET} ${X86_TARGET}

${TARGET}: ${TARGET}.elf
	${OBJCOPY} -O binary -S $^ $@

${TARGET}.elf: ${OBJS}
	${LD} -nostdlib -static -no-pie -Tkpimg.lds -o $@ $^

${X86_TARGET}: ${X86_TARGET}.elf
	${X86_OBJCOPY} -O binary -S $^ $@

${X86_TARGET}.elf: ${X86_OBJS} kpimg-x86.lds
	${X86_LD} -m elf_x86_64 -nostdlib -static -no-pie -Tkpimg-x86.lds -o $@ ${X86_OBJS}

x86/%.x86.o: x86/%.c
	${X86_CC} $(X86_CFLAGS) -Iinclude -I. -c -O2 -o $@ $<

x86/%.x86.o: x86/%.S
	${X86_CC} $(X86_CFLAGS) -Iinclude -I. -c -o $@ $<

%.x86.o: %.c
	${X86_CC} $(X86_CFLAGS) $(X86_INCLUDE) -c -O2 -o $@ $<

# puff needs INFLATE_ALLOW_INVALID_DISTANCE for the x86 build too
base/puff/puff.x86.o: base/puff/puff.c
	${X86_CC} $(X86_CFLAGS) $(X86_INCLUDE) -c -O2 -DINFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR -o $@ $<

# sha256 with -O0 to prevent compiler optimizations breaking crypto
base/sha256.x86.o: base/sha256.c
	${X86_CC} $(X86_CFLAGS) $(X86_INCLUDE) -c -O0 -o $@ $<

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE) -c -O2 -o $@ $<

base/sha256.o: base/sha256.c
	${CC} $(CFLAGS) $(INCLUDE) -c -O0 -o $@ $<

base/puff/puff.o: base/puff/puff.c
	${CC} $(CFLAGS) $(INCLUDE) -c -O2 -DINFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR -o $@ $<

%.o: %.S
	${CC} $(CFLAGS) $(INCLUDE) -c -o $@ $<

.PHONY: hdr x86
hdr:
	cp -Rf patch/include/uapi ../user/
	cp -f ../version ../user/
	cp -f include/preset.h ../tools/

x86: hdr ${X86_TARGET}

.PHONY: clean
clean:
	rm -rf kpimg kpimg.elf kpimg-x86 kpimg-x86.elf
	find . -name '*.o' | xargs rm -f
