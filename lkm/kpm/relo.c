// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Ported from kernel/patch/module/relo.c. Applies AArch64 RELA relocations to
 * a loaded KPM image. The encoder comes from insn.c.
 */
#include "insn.h"
#include "module.h"

#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/types.h>

enum kp_aarch64_reloc_op {
	RELOC_OP_NONE,
	RELOC_OP_ABS,
	RELOC_OP_PREL,
	RELOC_OP_PAGE,
};

static u64 do_reloc(enum kp_aarch64_reloc_op reloc_op, void *place, u64 val)
{
	switch (reloc_op) {
	case RELOC_OP_ABS:
		return val;
	case RELOC_OP_PREL:
		return val - (u64)place;
	case RELOC_OP_PAGE:
		return (val & ~0xfff) - ((u64)place & ~0xfff);
	case RELOC_OP_NONE:
		return 0;
	}

	pr_err("do_reloc: unknown relocation operation %d\n", reloc_op);
	return 0;
}

static int reloc_data(enum kp_aarch64_reloc_op op, void *place, u64 val, int len)
{
	u64 imm_mask = (1 << len) - 1;
	s64 sval = do_reloc(op, place, val);

	switch (len) {
	case 16:
		*(s16 *)place = sval;
		break;
	case 32:
		*(s32 *)place = sval;
		break;
	case 64:
		*(s64 *)place = sval;
		break;
	default:
		pr_err("Invalid length (%d) for data relocation\n", len);
		return 0;
	}

	/* Extract the upper value bits (including the sign bit) and
	 * shift them to bit 0. */
	sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);

	/* Overflow if the value is not representable in len bits. */
	if ((u64)(sval + 1) > 2)
		return -ERANGE;

	return 0;
}

static int reloc_insn_movw(enum kp_aarch64_reloc_op op, void *place, u64 val, int lsb,
			   enum kp_aarch64_insn_imm_type imm_type)
{
	u64 imm, limit = 0;
	s64 sval;
	u32 insn = *(u32 *)place;

	sval = do_reloc(op, place, val);
	sval >>= lsb;
	imm = sval & 0xffff;

	if (imm_type == KP_AARCH64_INSN_IMM_MOVNZ) {
		/* For signed MOVW relocations, manipulate the instruction
		 * encoding depending on whether the immediate is negative. */
		insn &= ~(3 << 29);
		if ((s64)imm >= 0) {
			/* >=0: MOVZ (opcode 10b). */
			insn |= 2 << 29;
		} else {
			/* <0: MOVN (opcode 00b), invert the immediate. */
			imm = ~imm;
		}
		imm_type = KP_AARCH64_INSN_IMM_MOVK;
	}

	insn = kp_aarch64_insn_encode_immediate(imm_type, insn, imm);
	*(u32 *)place = insn;

	sval >>= 16;

	/* For unsigned immediates, the sign bit is past the most significant
	 * bit of the field; AARCH64_INSN_IMM_16 is unsigned. */
	if (imm_type != KP_INSN_IMM_16) {
		sval++;
		limit++;
	}

	if ((u64)sval > limit)
		return -ERANGE;

	return 0;
}

static int reloc_insn_imm(enum kp_aarch64_reloc_op op, void *place, u64 val, int lsb, int len,
			  enum kp_aarch64_insn_imm_type imm_type)
{
	u64 imm, imm_mask;
	s64 sval;
	u32 insn = *(u32 *)place;

	sval = do_reloc(op, place, val);
	sval >>= lsb;
	imm_mask = (BIT(lsb + len) - 1) >> lsb;
	imm = sval & imm_mask;
	insn = kp_aarch64_insn_encode_immediate(imm_type, insn, imm);
	*(u32 *)place = insn;

	sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
	if ((u64)(sval + 1) >= 2)
		return -ERANGE;

	return 0;
}

int kp_apply_relocate(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex,
		      unsigned int relsec, struct kp_module *me)
{
	return 0;
}

int kp_apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex,
			  unsigned int relsec, struct kp_module *me)
{
	unsigned int i;
	int ovf;
	bool overflow_check;
	Elf64_Sym *sym;
	void *loc;
	u64 val;
	Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;

	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* loc corresponds to P in the AArch64 ELF document. */
		loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr + rel[i].r_offset;
		/* sym is the ELF symbol we're referring to. */
		sym = (Elf64_Sym *)sechdrs[symindex].sh_addr + ELF64_R_SYM(rel[i].r_info);
		/* val corresponds to (S + A) in the AArch64 ELF document. */
		val = sym->st_value + rel[i].r_addend;

		overflow_check = true;

		switch (ELF64_R_TYPE(rel[i].r_info)) {
		/* Null relocations. */
		case R_ARM_NONE:
		case R_AARCH64_NONE:
			ovf = 0;
			break;
		/* Data relocations. */
		case R_AARCH64_ABS64:
			overflow_check = false;
			ovf = reloc_data(RELOC_OP_ABS, loc, val, 64);
			break;
		case R_AARCH64_ABS32:
			ovf = reloc_data(RELOC_OP_ABS, loc, val, 32);
			break;
		case R_AARCH64_ABS16:
			ovf = reloc_data(RELOC_OP_ABS, loc, val, 16);
			break;
		case R_AARCH64_PREL64:
			overflow_check = false;
			ovf = reloc_data(RELOC_OP_PREL, loc, val, 64);
			break;
		case R_AARCH64_PREL32:
			ovf = reloc_data(RELOC_OP_PREL, loc, val, 32);
			break;
		case R_AARCH64_PREL16:
			ovf = reloc_data(RELOC_OP_PREL, loc, val, 16);
			break;

		/* MOVW instruction relocations. */
		case R_AARCH64_MOVW_UABS_G0_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_MOVW_UABS_G0:
			ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, KP_INSN_IMM_16);
			break;
		case R_AARCH64_MOVW_UABS_G1_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_MOVW_UABS_G1:
			ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, KP_INSN_IMM_16);
			break;
		case R_AARCH64_MOVW_UABS_G2_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_MOVW_UABS_G2:
			ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, KP_INSN_IMM_16);
			break;
		case R_AARCH64_MOVW_UABS_G3:
			overflow_check = false;
			ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 48, KP_INSN_IMM_16);
			break;
		case R_AARCH64_MOVW_SABS_G0:
			ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, KP_AARCH64_INSN_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_SABS_G1:
			ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, KP_AARCH64_INSN_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_SABS_G2:
			ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, KP_AARCH64_INSN_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_PREL_G0_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_MOVW_PREL_G0:
			ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0, KP_AARCH64_INSN_IMM_MOVK);
			break;
		case R_AARCH64_MOVW_PREL_G1_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_MOVW_PREL_G1:
			ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 16, KP_AARCH64_INSN_IMM_MOVK);
			break;
		case R_AARCH64_MOVW_PREL_G2_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_MOVW_PREL_G2:
			ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 32, KP_AARCH64_INSN_IMM_MOVK);
			break;
		case R_AARCH64_MOVW_PREL_G3:
			overflow_check = false;
			ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 48, KP_AARCH64_INSN_IMM_MOVNZ);
			break;
		/* Immediate instruction relocations. */
		case R_AARCH64_LD_PREL_LO19:
			ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, KP_INSN_IMM_19);
			break;
		case R_AARCH64_ADR_PREL_LO21:
			ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 0, 21, KP_INSN_IMM_ADR);
			break;
		case R_AARCH64_ADR_PREL_PG_HI21_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_ADR_PREL_PG_HI21:
			ovf = reloc_insn_imm(RELOC_OP_PAGE, loc, val, 12, 21, KP_INSN_IMM_ADR);
			break;
		case R_AARCH64_ADD_ABS_LO12_NC:
		case R_AARCH64_LDST8_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 0, 12, KP_INSN_IMM_12);
			break;
		case R_AARCH64_LDST16_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 1, 11, KP_INSN_IMM_12);
			break;
		case R_AARCH64_LDST32_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 2, 10, KP_INSN_IMM_12);
			break;
		case R_AARCH64_LDST64_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 3, 9, KP_INSN_IMM_12);
			break;
		case R_AARCH64_LDST128_ABS_LO12_NC:
			overflow_check = false;
			ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 4, 8, KP_INSN_IMM_12);
			break;
		case R_AARCH64_TSTBR14:
			ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 14, KP_INSN_IMM_14);
			break;
		case R_AARCH64_CONDBR19:
			ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, KP_INSN_IMM_19);
			break;
		case R_AARCH64_JUMP26:
		case R_AARCH64_CALL26:
			ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 26, KP_INSN_IMM_26);
			break;
		default:
			pr_err("unsupported RELA relocation: %llu\n", ELF64_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}

		if (overflow_check && ovf == -ERANGE)
			goto overflow;
	}
	return 0;
overflow:
	pr_err("overflow in relocation type %d val %llx\n", (int)ELF64_R_TYPE(rel[i].r_info), val);
	return -ENOEXEC;
}
