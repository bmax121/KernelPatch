OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(kpimg_x86_entry)

SECTIONS
{
    . = 0;
    _link_base = .;

    .setup.data : {
        _setup_start = .;
        KEEP(x86/setup.x86.o(.setup.header))
        . = _setup_start + 64;
        KEEP(x86/setup.x86.o(.setup.preset))
        _setup_payload_end = .;
        . = _setup_start + 2K;
    }
    ASSERT(_setup_payload_end <= _setup_start + 2K, "x86 setup data exceeds 2 KiB")

    .entry.text : {
        _x86_entry_start = .;
        KEEP(x86/entry.x86.o(.entry.text))
        x86/setup.x86.o(.text .text.*)
        x86/x86_start.x86.o(.text .text.*)
        *(.rodata .rodata.*)
        _x86_entry_end = .;
    }
    ASSERT(kpimg_x86_entry == 2K, "x86 entry offset must remain 0x800")

    . = ALIGN(4K);
    _kp_text_start = .;
    .kp.text : {
        *(.kp.text)
        *(EXCLUDE_FILE(x86/*.x86.o) .text .text.*)
        *(EXCLUDE_FILE(x86/*.x86.o) .rodata .rodata.*)
        _kp_text_end = .;
    }

    . = ALIGN(4K);
    _kp_data_start = .;
    .kp.data : {
        *(.start.data)
        *(EXCLUDE_FILE(x86/*.x86.o) .data .data.*)
        *(EXCLUDE_FILE(x86/*.x86.o) .bss .bss.* COMMON)
        . = ALIGN(16);
        _kp_symbol_start = .;
        *(.kp.symbol)
        _kp_symbol_end = .;
        _kp_data_end = .;
    }

    . = ALIGN(4K);
    _kp_end = .;

    _link_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
    }

    .got : { *(.got .got.*) }
    ASSERT(SIZEOF(.got) == 0, "unexpected x86 GOT entries")

    .got.plt : { *(.got.plt) }
    ASSERT(SIZEOF(.got.plt) == 0, "unexpected x86 GOT.PLT entries")

    .plt : { *(.plt .plt.* .iplt .igot .igot.plt) }
    ASSERT(SIZEOF(.plt) == 0, "unexpected x86 PLT entries")

    .rela.dyn : { *(.rela .rela.*) }
    ASSERT(SIZEOF(.rela.dyn) == 0, "unexpected x86 dynamic relocations")
}
