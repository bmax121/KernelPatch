KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ODIR := $(MDIR)

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))
$(info -- OUTPUT DIR: $(ODIR))

.PHONY: all clean

# Strip kernel-side alternatives from the .ko: the .altinstructions section is
# emitted against the build kernel's cpufeature numbering and ARM64_CB_PATCH
# (= ARM64_NCAPS) is a different number on every kernel. Loading a .ko into a
# kernel of another KMI reinterprets the entries — a foreign entry can be taken
# for an unconditional callback (alt_cb = ALT_REPL_PTR) and the loader then
# executes module-local code before the text is executable (IABT panic), while
# feature-gated entries patch module code with the wrong semantics. The kept
# original instruction sequences are the correct runtime fallbacks for every
# alternative the module emits, so removing the section is functionally safe.
OBJCOPY_BIN := $(shell command -v llvm-objcopy >/dev/null 2>&1 && echo llvm-objcopy || echo objcopy)

all:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) modules -j$(shell nproc)
	$(OBJCOPY_BIN) --remove-section .altinstructions --remove-section .rela.altinstructions $(ODIR)/kernelpatch.ko || \
		echo "warn: could not strip .altinstructions (continuing with them present)"

clean:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) clean

# Keep a new line here!! Because someone may append config
