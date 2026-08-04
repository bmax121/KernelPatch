// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Ported from kernel/patch/module/insn.c (aarch64_insn_encode_immediate only).
 */
#include "insn.h"

#include <linux/bits.h>
#include <linux/printk.h>

#include "../include/kp_lkm.h"

u32 kp_aarch64_insn_encode_immediate(enum kp_aarch64_insn_imm_type type, u32 insn, u64 imm)
{
	u32 immlo, immhi, lomask, himask, mask;
	int shift;

	switch (type) {
	case KP_INSN_IMM_ADR:
		lomask = 0x3;
		himask = 0x7ffff;
		immlo = imm & lomask;
		imm >>= 2;
		immhi = imm & himask;
		imm = (immlo << 24) | (immhi);
		mask = (lomask << 24) | (himask);
		shift = 5;
		break;
	case KP_INSN_IMM_26:
		mask = BIT(26) - 1;
		shift = 0;
		break;
	case KP_INSN_IMM_19:
		mask = BIT(19) - 1;
		shift = 5;
		break;
	case KP_INSN_IMM_16:
		mask = BIT(16) - 1;
		shift = 5;
		break;
	case KP_INSN_IMM_14:
		mask = BIT(14) - 1;
		shift = 5;
		break;
	case KP_INSN_IMM_12:
		mask = BIT(12) - 1;
		shift = 10;
		break;
	case KP_INSN_IMM_9:
		mask = BIT(9) - 1;
		shift = 12;
		break;
	case KP_INSN_IMM_7:
		mask = BIT(7) - 1;
		shift = 15;
		break;
	case KP_INSN_IMM_6:
	case KP_INSN_IMM_S:
		mask = BIT(6) - 1;
		shift = 10;
		break;
	case KP_INSN_IMM_R:
		mask = BIT(6) - 1;
		shift = 16;
		break;
	default:
		logke("kp insn encode: unknown immediate encoding %d\n", type);
		return 0;
	}

	insn &= ~(mask << shift);
	insn |= (imm & mask) << shift;

	return insn;
}
