/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Minimal AArch64 instruction-immediate encoder for KPM relocation. Only the
 * immediate-encoding enum and encoder used by relo.c are ported; the rest of
 * KP's insn.c (branch generation, hotpatch, ...) is out of scope for the LKM.
 */
#ifndef _KP_LKM_KPM_INSN_H_
#define _KP_LKM_KPM_INSN_H_

#include <linux/types.h>

enum kp_aarch64_insn_imm_type {
	KP_INSN_IMM_ADR,
	KP_INSN_IMM_26,
	KP_INSN_IMM_19,
	KP_INSN_IMM_16,
	KP_INSN_IMM_14,
	KP_INSN_IMM_12,
	KP_INSN_IMM_9,
	KP_INSN_IMM_7,
	KP_INSN_IMM_6,
	KP_INSN_IMM_S,
	KP_INSN_IMM_R,
	KP_INSN_IMM_MAX,
};

/* relo.c uses the KP original names; map them onto the ported enum. */
#define KP_AARCH64_INSN_IMM_MOVNZ KP_INSN_IMM_MAX
#define KP_AARCH64_INSN_IMM_MOVK KP_INSN_IMM_16

/* Encode @imm into the immediate field of AArch64 instruction @insn of type
 * @type, returning the modified instruction. */
u32 kp_aarch64_insn_encode_immediate(enum kp_aarch64_insn_imm_type type, u32 insn, u64 imm);

#endif /* _KP_LKM_KPM_INSN_H_ */
