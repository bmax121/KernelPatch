
#define __ASSEMBLY__
#include "../preset/preset.h"

    .equ STACK_SIZE, 2048

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

    .global setup
    .type setup, %function
setup:
    // Save
    stp x0, x1, [sp, -16]!
    stp x2, x3, [sp, -16]!

    // _link_base
    adrp x9, _link_base
    add x9, x9, :lo12:_link_base
    // preset
    adrp x10, preset
    add x10, x10, :lo12:preset
    // preset.kp_offset
    ldr x11, [x10, #setup_kp_offset_offset]
    // uint64 kernel_pa = (uint64_t)_link_base - preset.kp_offset;
    sub x12, x9, x11

    // map_prepare(kernel_pa)
    // mov x0, x12
    // bl map_prepare

    // memcpy32(kernel_pa, (uint64_t)preset.header_backup, sizeof(preset.header_backup));
    mov x0, x12
    add x1, x10, #setup_header_backup_offset
    mov x2, #HDR_BACKUP_SIZE
    bl memcpy32

    // I-cache = on or off,
    dsb ish
    ic iallu
    isb

    // Restore
    ldp x2, x3, [sp], 16
    ldp x0, x1, [sp], 16

    // _head
    mov x16, x12
    br x16



    .section .entry.text, "ax"
    .global entry
    .type entry, %function
entry:
    // x0 = physical address to the FDT blob.
    // Preserve the arguments passed by the bootloader in x0 .. x3
    adrp x4, stack
    add x4, x4, :lo12:stack
    add x4, x4, STACK_SIZE
    mov sp, x4
    b setup

#undef __ASSEMBLY__