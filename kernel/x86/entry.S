/* SPDX-License-Identifier: GPL-2.0-or-later */

.section .entry.text, "ax"
.globl kpimg_x86_entry
/* Called by the kernel-entry trampoline; preserve all GPRs and RFLAGS. */
kpimg_x86_entry:
    pushfq
    cld
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    subq $8, %rsp
    movw $0x3F8, %dx
    movb $'K', %al
    outb %al, %dx
    movb $'P', %al
    outb %al, %dx
    movb $'!', %al
    outb %al, %dx
    movb $'\n', %al
    outb %al, %dx
    movb $'\r', %al
    outb %al, %dx
    call kpimg_x86_start
    addq $8, %rsp

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    popfq
    ret

.section .note.GNU-stack, "", @progbits
