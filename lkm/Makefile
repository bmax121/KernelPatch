KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ODIR := $(MDIR)

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))
$(info -- OUTPUT DIR: $(ODIR))

.PHONY: all clean

all:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) modules -j$(shell nproc)

clean:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) clean

# Keep a new line here!! Because someone may append config
