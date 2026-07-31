/* SPDX-License-Identifier: GPL-2.0-or-later */

.section .text, "ax"
.globl setjmp
setjmp:
    movq %rbx, 0(%rdi)
    movq %rsp, 8(%rdi)
    movq %rbp, 16(%rdi)
    movq %r12, 24(%rdi)
    movq %r13, 32(%rdi)
    movq %r14, 40(%rdi)
    movq %r15, 48(%rdi)
    movq (%rsp), %rax           /* return address */
    movq %rax, 56(%rdi)
    xorl %eax, %eax
    ret

.globl longjmp
longjmp:
    movq 0(%rdi), %rbx
    movq 8(%rdi), %rsp
    movq 16(%rdi), %rbp
    movq 24(%rdi), %r12
    movq 32(%rdi), %r13
    movq 40(%rdi), %r14
    movq 48(%rdi), %r15
    movq 56(%rdi), %rax
    movq %rax, (%rsp)           /* restore return address */
    movl %esi, %eax
    testl %eax, %eax
    jnz 1f
    incl %eax                   /* ensure non-zero return */
1:
    ret
