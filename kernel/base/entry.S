
#define __ASSEMBLY__
#include "../preset/preset.h"
#include "./setup.h"
#include "./start.h"

//     .section .setup.data, "a"
//     .align 3
//     .global stack
// stack:
//     .space 2048

// - X0~X7：用于传递子程序参数和结果，使用时不需要保存，多余参数采用堆栈传递，64位返回结果采用X0表示，128位返回结果采用X1:X0表示。
// - X8：用于保存子程序返回地址， 尽量不要使用 。
// - X9~X15：临时寄存器，使用时不需要保存。
// - X16~X17：子程序内部调用寄存器，使用时不需要保存，尽量不要使用。
// - X18：平台寄存器，它的使用与平台相关，尽量不要使用。
// - X19~X28：临时寄存器，使用时必须保存。
// - X29：帧指针寄存器，用于连接栈帧，使用时需要保存。
// - X30：链接寄存器LR
// - X31：堆栈指针寄存器SP或零寄存器ZXR
// 子程序调用时必须要保存的寄存器：X19~X29和SP(X31)。
// 不需要保存的寄存器：X0~X7,X9~X15


.text
.align 2
.type memcpy, %function
memcpy:
    cmp x2, 0
    ble .end
.copy_loop:
    ldrb w22, [x1], 1
    strb w22, [x0], 1
    subs x2, x2, 1
    cbnz x2, .copy_loop
.end:
    ret


.text
.align 2
.type start_prepare, %function
start_prepare:
    stp x29, x30, [sp, -16]!
    stp x19, x20, [sp, -16]!
    // map_preset
    adrp x9, map_preset
    add x9, x9, :lo12:map_preset
    // preset
    adrp x10, preset
    add x10, x10, :lo12:preset
    // start_preset
    adrp x11, start_preset
    add x11, x11, :lo12:start_preset
    // start_preset.kernel_size = preset.kernel_size;
    ldr x12, [x10, #setup_kernel_size_offset]
    str x12, [x9, #start_kernel_size_offset]


    // Restore
    ldp x19, x20, [sp], 16 
    ldp x29, x30, [sp], 16
    ret

.text
.align 2
.type map_prepare, %function
map_prepare:
    stp x29, x30, [sp, -16]!
    stp x19, x20, [sp, -16]!
    // map_preset
    adrp x9, map_preset
    add x9, x9, :lo12:map_preset
    // preset
    adrp x10, preset
    add x10, x10, :lo12:preset
    // map_preset.kernel_pa = kernel_pa;
    str x1, [x9, #map_kernel_pa_offset]
    // map_preset.map_offset = preset.map_offset;
    ldr x11, [x10, #setup_map_offset_offset]
    str x11, [x9, #map_map_offset_offset]
    mov x14, x11
    // map_preset.paging_init_relo = preset.paging_init_offset;
    ldr x11, [x10, #setup_paging_init_offset_offset]
    str x11, [x9, #map_paging_init_relo_offset]
    mov x15, x11
    // map_preset.memblock_reserve_relo = preset.memblock_reserve_offset;
    ldr x11, [x10, #setup_memblock_reserve_offset_offset]
    str x11, [x9, #map_memblock_reserve_relo_offset]
    // map_preset.memblock_alloc_try_nid_relo = preset.memblock_alloc_try_nid_offset;
    ldr x11, [x10, #setup_memblock_reserve_offset_offset]
    str x11, [x9, #map_memblock_reserve_relo_offset]
    // map_preset.vabits_actual_relo = preset.vabits_actual_offset 
    ldr x11, [x10, #setup_vabits_actual_offset_offset]
    str x11, [x9, #map_vabits_actual_relo_offset]
    // map_preset.memstart_addr_relo = preset.memstart_addr_offset 
    ldr x11, [x10, #setup_memstart_addr_offset_offset]
    str x11, [x9, #map_memstart_addr_relo_offset]
    // map_preset.kimage_voffset_relo = preset.kimage_voffset_offset 
    ldr x11, [x10, #setup_kimage_voffset_offset_offset]
    str x11, [x9, #map_kimage_voffset_relo_offset]
#ifdef MAP_DEBUG
    // map_preset.printk_relo = preset.printk_offset;
    ldr x11, [x10, #setup_printk_offset_offset]
    str x11, [x9, #map_printk_relo_offset]
    // map_preset.kallsyms_lookup_name_relo = preset.kallsyms_lookup_name_offset;
    ldr x11, [x10, #setup_kallsyms_lookup_name_offset_offset]
    str x11, [x9, #map_kallsyms_lookup_name_relo_offset]
#endif

    // backup and hook paging_init
    // uint64_t paging_init_pa = paging_init_offset + kernel_pa;
    add x13, x15, x0
    // // map_preset.paging_init_backup = *(uint32_t *)(paging_init_pa);
    ldr w12, [x13]
    str w12, [x9, #map_paging_init_backup_offset]
    // uint64_t replace_offset = (uint64_t)(_paging_init - _map_start) + map_offset;
    adrp x11, _paging_init
    add x11, x11, :lo12:_paging_init
    adrp x12, _map_start
    add x12, x12, :lo12:_map_start
    sub x11, x11, x12
    add x11, x11, x14
    // #define B_REL(src, dst) (0x14000000u | (((dst - src) & 0x0FFFFFFFu) >> 2u))
    sub x15, x11, x15
    ubfx w15, w15, #2, #26
    mov w12, #0x14000000
    orr w15, w15, w12
    // *(uint32_t *)paging_init_pa = B_REL(paging_init_offset, replace_offset);
    str w15, [x13]

    // relocate map
    // _map_end
    adrp x2, _map_end
    add x2, x2, :lo12:_map_end
    // uint64_t from = (uint64_t)_map_start;
    adrp x1, _map_start
    add x1, x1, :lo12:_map_start
    // int64_t size = (int64_t)(_map_end - _map_start);
    sub x2, x2, x1
    // uint64_t to = preset.map_offset + kernel_pa;
    add x0, x0, x14
    // memcpy(to, from, size);
    bl memcpy
    // Restore
    ldp x19, x20, [sp], 16
    ldp x29, x30, [sp], 16
    ret

.text
.align 2
.type setup, %function
setup:
    // Save
    stp x29, x30, [sp, -16]!
    stp x0, x1, [sp, -16]!
    stp x2, x3, [sp, -16]!
    stp x19, x20, [sp, -16]!

    // _link_base
    adrp x9, _link_base
    add x9, x9, :lo12:_link_base
    // preset
    adrp x10, preset
    add x10, x10, :lo12:preset
    mov x20, x10
    // preset.kp_offset
    ldrsw x11, [x10, #setup_kp_offset_offset]
    // uint64 kernel_pa = (uint64_t)_link_base - preset.kp_offset;
    sub x12, x9, x11
    mov x19, x12

    // map_prepare(kernel_pa)
    mov x0, x19
    bl map_prepare
    // hook_paging_init(kernel_pa)
    mov x0, x19
    // bl hook_paging_init

    // memcpy32(kernel_pa, (uint64_t)preset.header_backup, sizeof(preset.header_backup));
    mov x0, x19
    add x1, x20, #setup_header_backup_offset
    mov x2, #HDR_BACKUP_SIZE
    // bl rmemcpy32
    bl memcpy

    // I-cache = on or off,
    dsb ish
    ic iallu
    isb

    mov x16, x19
    // Restore
    ldp x19, x20, [sp], 16
    ldp x2, x3, [sp], 16
    ldp x0, x1, [sp], 16
    ldp x29, x30, [sp], 16
    // Restore sp
    ldp x9, x10, [sp], 16
    mov sp, x9
    // _head
    br x16


.section .entry.text, "ax"
.global entry
.type entry, %function
entry:
    // x0 = physical address to the FDT blob.
    // Preserve the arguments passed by the bootloader in x0 .. x3
    mov x9, sp
    adrp x11, stack
    add x11, x11, :lo12:stack
    add x11, x11, STACK_SIZE
    mov sp, x11
    stp x9, x10, [sp, -16]! 
    b setup

#undef __ASSEMBLY__