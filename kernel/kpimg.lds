OUTPUT_ARCH(aarch64)

_link_base = 64k - 3 * 4k;

SECTIONS 
{
    . = _link_base;
    _link_base = .;

    .setup.data : {
        _setup_start = .;
        base/setup.o(.setup.header)
        . = _setup_start + 64;
        base/setup.o(.setup.preset)
        base/setup.o(.setup.data)
        . = _setup_start + 4K;
    }
    
    .setup.text : {
        base/setup1.o(.entry.text)
        base/setup1.o(.text)
        base/setup.o(.text)
        _setup_end = .;
    }

    . = ALIGN(16);
    .setup.map : {
        _map_start = .;
        base/map.o(.map.data)
        base/map.o(.map.text)
        base/map.o(.text)
        . = ALIGN(16);
        _map_end = .;
    }
    ASSERT(SIZEOF(.setup.map) < 0xa00, "Size too large of .setup.map!")

    . = ALIGN(64K);
    _kp_start = .;
    .kp.text : {
        _kp_text_start = .;

        base/start.o(.start.text)
        base/start.o(.text)
        base/hook.o(.transit0.text);
        _transit0_end = .;
        base/hook.o(.transit1.text);
        _transit1_end = .;
        base/hook.o(.transit2.text);
        _transit2_end = .;
        base/hook.o(.transit3.text);
        _transit3_end = .;
        base/hook.o(.transit4.text);
        _transit4_end = .;
        base/hook.o(.transit8.text);
        _transit8_end = .;
        base/hook.o(.transit12.text);
        _transit12_end = .;

        base/*(.text)
        base/*(.rodata*)

        *(.text)
        *(.rodata*)
        /*  *(.got) */

        . = ALIGN(16);
        _kp_text_end = .;
    }

    . = ALIGN(64k);
    .kp.data : {
        _kp_data_start = .;
        base/start.o(.start.data)
        base/*(data)
        base/*(.bss)
        *(.data)
        *(.bss)
        _kp_data_end = .;
    }

    .got.plt : { *(.got.plt) }
    /* ASSERT(SIZEOF(.got.plt) == 0 || SIZEOF(.got.plt) == 0x18, "Unexpected GOT/PLT entries detected!") */
    ASSERT(SIZEOF(.got.plt) == 0, "Unexpected GOT/PLT entries detected!")

    . = ALIGN(64k);
    _kp_end = .;

    _link_end = .;

    .got : {
        *(.got)
    }
    ASSERT(SIZEOF(.got) == 0, "Unexpected GOT detected!")
    
    .plt : {
        *(.plt) *(.plt.*) *(.iplt) *(.igot .igot.plt)
    }
    ASSERT(SIZEOF(.plt) == 0, "Unexpected run-time procedure linkages detected!")


    .data.rel.ro : { 
        *(.data.rel.ro) 
    }
    ASSERT(SIZEOF(.data.rel.ro) == 0, "Unexpected RELRO detected!")
    
    .rela.dyn : {
        *(.rela .rela*)
    }
    ASSERT(SIZEOF(.rela.dyn) == 0, "Unexpected RELRDYN detected!")
}