/* SPDX-License-Identifier: GPL-2.0-or-later */

.section .text, "ax"
.globl flush_icache_range

flush_icache_range:
    /* x86 has coherent I/D caches; WBINVD for paranoia on early x86-64 */
    wbinvd
    ret
