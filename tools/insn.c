/*
 * Copyright (C) 2013 Huawei Ltd.
 * Author: Jiang Liu <liuj97@gmail.com>
 *
 * Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Linux source: /arch/arm64/kernel/insn.c
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "insn.h"
#include "ptrace.h"
#include "fls_ffs.h"

#define BUG()                                                                           \
    do {                                                                                \
        fprintf(stdout, "BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
        do {                                                                            \
        } while (0);                                                                    \
        exit(-EINVAL);                                                                  \
    } while (0)

#define BUG_ON(condition)     \
    do {                      \
        if (condition) BUG(); \
    } while (0)

#define le32_to_cpu(x) (x)
#define cpu_to_le32(x) (x)

#define SZ_1 0x00000001
#define SZ_2 0x00000002
#define SZ_4 0x00000004
#define SZ_8 0x00000008
#define SZ_16 0x00000010
#define SZ_32 0x00000020
#define SZ_64 0x00000040
#define SZ_128 0x00000080
#define SZ_256 0x00000100
#define SZ_512 0x00000200

#define SZ_1K 0x00000400
#define SZ_2K 0x00000800
#define SZ_4K 0x00001000
#define SZ_8K 0x00002000
#define SZ_16K 0x00004000
#define SZ_32K 0x00008000
#define SZ_64K 0x00010000
#define SZ_128K 0x00020000
#define SZ_256K 0x00040000
#define SZ_512K 0x00080000

#define SZ_1M 0x00100000
#define SZ_2M 0x00200000
#define SZ_4M 0x00400000
#define SZ_8M 0x00800000
#define SZ_16M 0x01000000
#define SZ_32M 0x02000000
#define SZ_64M 0x04000000
#define SZ_128M 0x08000000
#define SZ_256M 0x10000000
#define SZ_512M 0x20000000

#define SZ_1G 0x40000000
#define SZ_2G 0x80000000

#define BITS_PER_LONG 64

static inline uint64_t __ffs64(u64 word)
{
    return __ffs((uint64_t)word);
}

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32)(n))

static inline uint64_t hweight64(u64 w)
{
    u64 res = w - ((w >> 1) & 0x5555555555555555ul);
    res = (res & 0x3333333333333333ul) + ((res >> 2) & 0x3333333333333333ul);
    res = (res + (res >> 4)) & 0x0F0F0F0F0F0F0F0Ful;
    res = res + (res >> 8);
    res = res + (res >> 16);
    return (res + (res >> 32)) & 0x00000000000000FFul;
}

/*
 * Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example
 * GENMASK_ULL(39, 21) gives us the 64bit vector 0x000000ffffe00000.
 */
#ifndef _WIN32
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#else 
#define GENMASK GENMASK_ULL
#define BITS_PER_LONG_LONG 64
#endif
#define GENMASK_ULL(h, l) (((~0ULL) << (l)) & (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))

/*
 * #imm16 values used for BRK instruction generation
 * Allowed values for kgbd are 0x400 - 0x7ff
 * 0x100: for triggering a fault on purpose (reserved)
 * 0x400: for dynamic BRK instruction
 * 0x401: for compile time BRK instruction
 */
#define FAULT_BRK_IMM 0x100
#define KGDB_DYN_DBG_BRK_IMM 0x400
#define KGDB_COMPILED_DBG_BRK_IMM 0x401

/*
 * BRK instruction encoding
 * The #imm16 value should be placed at bits[20:5] within BRK ins
 */
#define AARCH64_BREAK_MON 0xd4200000

/*
 * BRK instruction for provoking a fault on purpose
 * Unlike kgdb, #imm16 value with unallocated handler is used for faulting.
 */
#define AARCH64_BREAK_FAULT (AARCH64_BREAK_MON | (FAULT_BRK_IMM << 5))

#define BIT(nr) (1ul << (nr))

#define AARCH64_INSN_SF_BIT BIT(31)
#define AARCH64_INSN_N_BIT BIT(22)
#define AARCH64_INSN_LSL_12 BIT(22)

static int aarch64_insn_encoding_class[] = {
    AARCH64_INSN_CLS_UNKNOWN, AARCH64_INSN_CLS_UNKNOWN, AARCH64_INSN_CLS_UNKNOWN, AARCH64_INSN_CLS_UNKNOWN,
    AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_REG,  AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_FPSIMD,
    AARCH64_INSN_CLS_DP_IMM,  AARCH64_INSN_CLS_DP_IMM,  AARCH64_INSN_CLS_BR_SYS,  AARCH64_INSN_CLS_BR_SYS,
    AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_REG,  AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_FPSIMD,
};

enum aarch64_insn_encoding_class aarch64_get_insn_class(u32 insn)
{
    return aarch64_insn_encoding_class[(insn >> 25) & 0xf];
}

/* NOP is an alias of HINT */
bool aarch64_insn_is_nop(u32 insn)
{
    if (!aarch64_insn_is_hint(insn)) return false;

    switch (insn & 0xFE0) {
    case AARCH64_INSN_HINT_YIELD:
    case AARCH64_INSN_HINT_WFE:
    case AARCH64_INSN_HINT_WFI:
    case AARCH64_INSN_HINT_SEV:
    case AARCH64_INSN_HINT_SEVL:
        return false;
    default:
        return true;
    }
}

bool aarch64_insn_is_branch_imm(u32 insn)
{
    return (aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn) || aarch64_insn_is_tbz(insn) ||
            aarch64_insn_is_tbnz(insn) || aarch64_insn_is_cbz(insn) || aarch64_insn_is_cbnz(insn) ||
            aarch64_insn_is_bcond(insn));
}

bool aarch64_insn_uses_literal(u32 insn)
{
    /* ldr/ldrsw (literal), prfm */

    return aarch64_insn_is_ldr_lit(insn) || aarch64_insn_is_ldrsw_lit(insn) || aarch64_insn_is_adr_adrp(insn) ||
           aarch64_insn_is_prfm_lit(insn);
}

bool aarch64_insn_is_branch(u32 insn)
{
    /* b, bl, cb*, tb*, b.cond, br, blr */

    return aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn) || aarch64_insn_is_cbz(insn) ||
           aarch64_insn_is_cbnz(insn) || aarch64_insn_is_tbz(insn) || aarch64_insn_is_tbnz(insn) ||
           aarch64_insn_is_ret(insn) || aarch64_insn_is_br(insn) || aarch64_insn_is_blr(insn) ||
           aarch64_insn_is_bcond(insn);
}

static int aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type, u32 *maskp, int *shiftp)
{
    u32 mask;
    int shift;

    switch (type) {
    case AARCH64_INSN_IMM_26:
        mask = BIT(26) - 1;
        shift = 0;
        break;
    case AARCH64_INSN_IMM_19:
        mask = BIT(19) - 1;
        shift = 5;
        break;
    case AARCH64_INSN_IMM_16:
        mask = BIT(16) - 1;
        shift = 5;
        break;
    case AARCH64_INSN_IMM_14:
        mask = BIT(14) - 1;
        shift = 5;
        break;
    case AARCH64_INSN_IMM_12:
        mask = BIT(12) - 1;
        shift = 10;
        break;
    case AARCH64_INSN_IMM_9:
        mask = BIT(9) - 1;
        shift = 12;
        break;
    case AARCH64_INSN_IMM_7:
        mask = BIT(7) - 1;
        shift = 15;
        break;
    case AARCH64_INSN_IMM_6:
    case AARCH64_INSN_IMM_S:
        mask = BIT(6) - 1;
        shift = 10;
        break;
    case AARCH64_INSN_IMM_R:
        mask = BIT(6) - 1;
        shift = 16;
        break;
    case AARCH64_INSN_IMM_N:
        mask = 1;
        shift = 22;
        break;
    default:
        return -EINVAL;
    }

    *maskp = mask;
    *shiftp = shift;

    return 0;
}

#define ADR_IMM_HILOSPLIT 2
#define ADR_IMM_SIZE SZ_2M
#define ADR_IMM_LOMASK ((1 << ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_HIMASK ((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_LOSHIFT 29
#define ADR_IMM_HISHIFT 5

u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
{
    u32 immlo, immhi, mask;
    int shift;

    switch (type) {
    case AARCH64_INSN_IMM_ADR:
        shift = 0;
        immlo = (insn >> ADR_IMM_LOSHIFT) & ADR_IMM_LOMASK;
        immhi = (insn >> ADR_IMM_HISHIFT) & ADR_IMM_HIMASK;
        insn = (immhi << ADR_IMM_HILOSPLIT) | immlo;
        mask = ADR_IMM_SIZE - 1;
        break;
    default:
        if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
            fprintf(stdout, "aarch64_insn_decode_immediate: unknown immediate encoding %d\n", type);
            return 0;
        }
    }

    return (insn >> shift) & mask;
}

u32 aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type, u32 insn, u64 imm)
{
    u32 immlo, immhi, mask;
    int shift;

    if (insn == AARCH64_BREAK_FAULT) return AARCH64_BREAK_FAULT;

    switch (type) {
    case AARCH64_INSN_IMM_ADR:
        shift = 0;
        immlo = (imm & ADR_IMM_LOMASK) << ADR_IMM_LOSHIFT;
        imm >>= ADR_IMM_HILOSPLIT;
        immhi = (imm & ADR_IMM_HIMASK) << ADR_IMM_HISHIFT;
        imm = immlo | immhi;
        mask = ((ADR_IMM_LOMASK << ADR_IMM_LOSHIFT) | (ADR_IMM_HIMASK << ADR_IMM_HISHIFT));
        break;
    default:
        if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
            fprintf(stdout, "aarch64_insn_encode_immediate: unknown immediate encoding %d\n", type);
            return AARCH64_BREAK_FAULT;
        }
    }

    /* Update the immediate field. */
    insn &= ~(mask << shift);
    insn |= (imm & mask) << shift;

    return insn;
}

u32 aarch64_insn_decode_register(enum aarch64_insn_register_type type, u32 insn)
{
    int shift;

    switch (type) {
    case AARCH64_INSN_REGTYPE_RT:
    case AARCH64_INSN_REGTYPE_RD:
        shift = 0;
        break;
    case AARCH64_INSN_REGTYPE_RN:
        shift = 5;
        break;
    case AARCH64_INSN_REGTYPE_RT2:
    case AARCH64_INSN_REGTYPE_RA:
        shift = 10;
        break;
    case AARCH64_INSN_REGTYPE_RM:
        shift = 16;
        break;
    default:
        fprintf(stdout, "%s: unknown register type encoding %d\n", __func__, type);
        return 0;
    }

    return (insn >> shift) & GENMASK(4, 0);
}

static u32 aarch64_insn_encode_register(enum aarch64_insn_register_type type, u32 insn, enum aarch64_insn_register reg)
{
    int shift;

    if (insn == AARCH64_BREAK_FAULT) return AARCH64_BREAK_FAULT;

    if (reg < AARCH64_INSN_REG_0 || reg > AARCH64_INSN_REG_SP) {
        fprintf(stdout, "%s: unknown register encoding %d\n", __func__, reg);
        return AARCH64_BREAK_FAULT;
    }

    switch (type) {
    case AARCH64_INSN_REGTYPE_RT:
    case AARCH64_INSN_REGTYPE_RD:
        shift = 0;
        break;
    case AARCH64_INSN_REGTYPE_RN:
        shift = 5;
        break;
    case AARCH64_INSN_REGTYPE_RT2:
    case AARCH64_INSN_REGTYPE_RA:
        shift = 10;
        break;
    case AARCH64_INSN_REGTYPE_RM:
    case AARCH64_INSN_REGTYPE_RS:
        shift = 16;
        break;
    default:
        fprintf(stdout, "%s: unknown register type encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    insn &= ~(GENMASK(4, 0) << shift);
    insn |= reg << shift;

    return insn;
}

static u32 aarch64_insn_encode_ldst_size(enum aarch64_insn_size_type type, u32 insn)
{
    u32 size;

    switch (type) {
    case AARCH64_INSN_SIZE_8:
        size = 0;
        break;
    case AARCH64_INSN_SIZE_16:
        size = 1;
        break;
    case AARCH64_INSN_SIZE_32:
        size = 2;
        break;
    case AARCH64_INSN_SIZE_64:
        size = 3;
        break;
    default:
        fprintf(stdout, "%s: unknown size encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    insn &= ~GENMASK(31, 30);
    insn |= size << 30;

    return insn;
}

static inline int64_t branch_imm_common(uint64_t pc, uint64_t addr, int64_t range)
{
    int64_t offset;

    if ((pc & 0x3) || (addr & 0x3)) {
        fprintf(stdout, "%s: A64 instructions must be word aligned\n", __func__);
        return range;
    }

    offset = ((long)addr - (long)pc);

    if (offset < -range || offset >= range) {
        fprintf(stdout, "%s: offset out of range\n", __func__);
        return range;
    }

    return offset;
}

u32 aarch64_insn_gen_branch_imm(uint64_t pc, uint64_t addr, enum aarch64_insn_branch_type type)
{
    u32 insn;
    int64_t offset;

    /*
	 * B/BL support [-128M, 128M) offset
	 * ARM64 virtual address arrangement guarantees all kernel and module
	 * texts are within +/-128M.
	 */
    offset = branch_imm_common(pc, addr, SZ_128M);
    if (offset >= SZ_128M) return AARCH64_BREAK_FAULT;

    switch (type) {
    case AARCH64_INSN_BRANCH_LINK:
        insn = aarch64_insn_get_bl_value();
        break;
    case AARCH64_INSN_BRANCH_NOLINK:
        insn = aarch64_insn_get_b_value();
        break;
    default:
        fprintf(stdout, "%s: unknown branch encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_26, insn, offset >> 2);
}

u32 aarch64_insn_gen_comp_branch_imm(uint64_t pc, uint64_t addr, enum aarch64_insn_register reg,
                                     enum aarch64_insn_variant variant, enum aarch64_insn_branch_type type)
{
    u32 insn;
    int64_t offset;

    offset = branch_imm_common(pc, addr, SZ_1M);
    if (offset >= SZ_1M) return AARCH64_BREAK_FAULT;

    switch (type) {
    case AARCH64_INSN_BRANCH_COMP_ZERO:
        insn = aarch64_insn_get_cbz_value();
        break;
    case AARCH64_INSN_BRANCH_COMP_NONZERO:
        insn = aarch64_insn_get_cbnz_value();
        break;
    default:
        fprintf(stdout, "%s: unknown branch encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT, insn, reg);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_19, insn, offset >> 2);
}

u32 aarch64_insn_gen_cond_branch_imm(uint64_t pc, uint64_t addr, enum aarch64_insn_condition cond)
{
    u32 insn;
    int64_t offset;

    offset = branch_imm_common(pc, addr, SZ_1M);

    insn = aarch64_insn_get_bcond_value();

    if (cond < AARCH64_INSN_COND_EQ || cond > AARCH64_INSN_COND_AL) {
        fprintf(stdout, "%s: unknown condition encoding %d\n", __func__, cond);
        return AARCH64_BREAK_FAULT;
    }
    insn |= cond;

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_19, insn, offset >> 2);
}

u32 aarch64_insn_gen_hint(enum aarch64_insn_hint_op op)
{
    return aarch64_insn_get_hint_value() | op;
}

u32 aarch64_insn_gen_nop(void)
{
    return aarch64_insn_gen_hint(AARCH64_INSN_HINT_NOP);
}

u32 aarch64_insn_gen_branch_reg(enum aarch64_insn_register reg, enum aarch64_insn_branch_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_BRANCH_NOLINK:
        insn = aarch64_insn_get_br_value();
        break;
    case AARCH64_INSN_BRANCH_LINK:
        insn = aarch64_insn_get_blr_value();
        break;
    case AARCH64_INSN_BRANCH_RETURN:
        insn = aarch64_insn_get_ret_value();
        break;
    default:
        fprintf(stdout, "%s: unknown branch encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, reg);
}

u32 aarch64_insn_gen_load_store_reg(enum aarch64_insn_register reg, enum aarch64_insn_register base,
                                    enum aarch64_insn_register offset, enum aarch64_insn_size_type size,
                                    enum aarch64_insn_ldst_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_LDST_LOAD_REG_OFFSET:
        insn = aarch64_insn_get_ldr_reg_value();
        break;
    case AARCH64_INSN_LDST_STORE_REG_OFFSET:
        insn = aarch64_insn_get_str_reg_value();
        break;
    default:
        fprintf(stdout, "%s: unknown load/store encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_ldst_size(size, insn);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT, insn, reg);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, base);

    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, offset);
}

u32 aarch64_insn_gen_load_store_pair(enum aarch64_insn_register reg1, enum aarch64_insn_register reg2,
                                     enum aarch64_insn_register base, int offset, enum aarch64_insn_variant variant,
                                     enum aarch64_insn_ldst_type type)
{
    u32 insn;
    int shift;

    switch (type) {
    case AARCH64_INSN_LDST_LOAD_PAIR_PRE_INDEX:
        insn = aarch64_insn_get_ldp_pre_value();
        break;
    case AARCH64_INSN_LDST_STORE_PAIR_PRE_INDEX:
        insn = aarch64_insn_get_stp_pre_value();
        break;
    case AARCH64_INSN_LDST_LOAD_PAIR_POST_INDEX:
        insn = aarch64_insn_get_ldp_post_value();
        break;
    case AARCH64_INSN_LDST_STORE_PAIR_POST_INDEX:
        insn = aarch64_insn_get_stp_post_value();
        break;
    default:
        fprintf(stdout, "%s: unknown load/store encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        if ((offset & 0x3) || (offset < -256) || (offset > 252)) {
            fprintf(stdout, "%s: offset must be multiples of 4 in the range of [-256, 252] %d\n", __func__, offset);
            return AARCH64_BREAK_FAULT;
        }
        shift = 2;
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        if ((offset & 0x7) || (offset < -512) || (offset > 504)) {
            fprintf(stdout, "%s: offset must be multiples of 8 in the range of [-512, 504] %d\n", __func__, offset);
            return AARCH64_BREAK_FAULT;
        }
        shift = 3;
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT, insn, reg1);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT2, insn, reg2);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, base);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_7, insn, offset >> shift);
}

u32 aarch64_insn_gen_load_store_ex(enum aarch64_insn_register reg, enum aarch64_insn_register base,
                                   enum aarch64_insn_register state, enum aarch64_insn_size_type size,
                                   enum aarch64_insn_ldst_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_LDST_LOAD_EX:
        insn = aarch64_insn_get_load_ex_value();
        break;
    case AARCH64_INSN_LDST_STORE_EX:
        insn = aarch64_insn_get_store_ex_value();
        break;
    default:
        fprintf(stdout, "%s: unknown load/store exclusive encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_ldst_size(size, insn);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT, insn, reg);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, base);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT2, insn, AARCH64_INSN_REG_ZR);

    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RS, insn, state);
}

static u32 aarch64_insn_encode_prfm_imm(enum aarch64_insn_prfm_type type, enum aarch64_insn_prfm_target target,
                                        enum aarch64_insn_prfm_policy policy, u32 insn)
{
    u32 imm_type = 0, imm_target = 0, imm_policy = 0;

    switch (type) {
    case AARCH64_INSN_PRFM_TYPE_PLD:
        break;
    case AARCH64_INSN_PRFM_TYPE_PLI:
        imm_type = BIT(0);
        break;
    case AARCH64_INSN_PRFM_TYPE_PST:
        imm_type = BIT(1);
        break;
    default:
        fprintf(stdout, "%s: unknown prfm type encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    switch (target) {
    case AARCH64_INSN_PRFM_TARGET_L1:
        break;
    case AARCH64_INSN_PRFM_TARGET_L2:
        imm_target = BIT(0);
        break;
    case AARCH64_INSN_PRFM_TARGET_L3:
        imm_target = BIT(1);
        break;
    default:
        fprintf(stdout, "%s: unknown prfm target encoding %d\n", __func__, target);
        return AARCH64_BREAK_FAULT;
    }

    switch (policy) {
    case AARCH64_INSN_PRFM_POLICY_KEEP:
        break;
    case AARCH64_INSN_PRFM_POLICY_STRM:
        imm_policy = BIT(0);
        break;
    default:
        fprintf(stdout, "%s: unknown prfm policy encoding %d\n", __func__, policy);
        return AARCH64_BREAK_FAULT;
    }

    /* In this case, imm5 is encoded into Rt field. */
    insn &= ~GENMASK(4, 0);
    insn |= imm_policy | (imm_target << 1) | (imm_type << 3);

    return insn;
}

u32 aarch64_insn_gen_prefetch(enum aarch64_insn_register base, enum aarch64_insn_prfm_type type,
                              enum aarch64_insn_prfm_target target, enum aarch64_insn_prfm_policy policy)
{
    u32 insn = aarch64_insn_get_prfm_value();

    insn = aarch64_insn_encode_ldst_size(AARCH64_INSN_SIZE_64, insn);

    insn = aarch64_insn_encode_prfm_imm(type, target, policy, insn);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, base);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_12, insn, 0);
}

u32 aarch64_insn_gen_add_sub_imm(enum aarch64_insn_register dst, enum aarch64_insn_register src, int imm,
                                 enum aarch64_insn_variant variant, enum aarch64_insn_adsb_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_ADSB_ADD:
        insn = aarch64_insn_get_add_imm_value();
        break;
    case AARCH64_INSN_ADSB_SUB:
        insn = aarch64_insn_get_sub_imm_value();
        break;
    case AARCH64_INSN_ADSB_ADD_SETFLAGS:
        insn = aarch64_insn_get_adds_imm_value();
        break;
    case AARCH64_INSN_ADSB_SUB_SETFLAGS:
        insn = aarch64_insn_get_subs_imm_value();
        break;
    default:
        fprintf(stdout, "%s: unknown add/sub encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    /* We can't encode more than a 24bit value (12bit + 12bit shift) */
    if (imm & ~(BIT(24) - 1)) goto out;

    /* If we have something in the top 12 bits... */
    if (imm & ~(SZ_4K - 1)) {
        /* ... and in the low 12 bits -> error */
        if (imm & (SZ_4K - 1)) goto out;

        imm >>= 12;
        insn |= AARCH64_INSN_LSL_12;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_12, insn, imm);

out:
    fprintf(stdout, "%s: invalid immediate encoding %d\n", __func__, imm);
    return AARCH64_BREAK_FAULT;
}

u32 aarch64_insn_gen_bitfield(enum aarch64_insn_register dst, enum aarch64_insn_register src, int immr, int imms,
                              enum aarch64_insn_variant variant, enum aarch64_insn_bitfield_type type)
{
    u32 insn;
    u32 mask;

    switch (type) {
    case AARCH64_INSN_BITFIELD_MOVE:
        insn = aarch64_insn_get_bfm_value();
        break;
    case AARCH64_INSN_BITFIELD_MOVE_UNSIGNED:
        insn = aarch64_insn_get_ubfm_value();
        break;
    case AARCH64_INSN_BITFIELD_MOVE_SIGNED:
        insn = aarch64_insn_get_sbfm_value();
        break;
    default:
        fprintf(stdout, "%s: unknown bitfield encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        mask = GENMASK(4, 0);
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT | AARCH64_INSN_N_BIT;
        mask = GENMASK(5, 0);
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    if (immr & ~mask) {
        fprintf(stdout, "%s: invalid immr encoding %d\n", __func__, immr);
        return AARCH64_BREAK_FAULT;
    }
    if (imms & ~mask) {
        fprintf(stdout, "%s: invalid imms encoding %d\n", __func__, imms);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);

    insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_R, insn, immr);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_S, insn, imms);
}

u32 aarch64_insn_gen_movewide(enum aarch64_insn_register dst, int imm, int shift, enum aarch64_insn_variant variant,
                              enum aarch64_insn_movewide_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_MOVEWIDE_ZERO:
        insn = aarch64_insn_get_movz_value();
        break;
    case AARCH64_INSN_MOVEWIDE_KEEP:
        insn = aarch64_insn_get_movk_value();
        break;
    case AARCH64_INSN_MOVEWIDE_INVERSE:
        insn = aarch64_insn_get_movn_value();
        break;
    default:
        fprintf(stdout, "%s: unknown movewide encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    if (imm & ~(SZ_64K - 1)) {
        fprintf(stdout, "%s: invalid immediate encoding %d\n", __func__, imm);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        if (shift != 0 && shift != 16) {
            fprintf(stdout, "%s: invalid shift encoding %d\n", __func__, shift);
            return AARCH64_BREAK_FAULT;
        }
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        if (shift != 0 && shift != 16 && shift != 32 && shift != 48) {
            fprintf(stdout, "%s: invalid shift encoding %d\n", __func__, shift);
            return AARCH64_BREAK_FAULT;
        }
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    insn |= (shift >> 4) << 21;

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_16, insn, imm);
}

u32 aarch64_insn_gen_add_sub_shifted_reg(enum aarch64_insn_register dst, enum aarch64_insn_register src,
                                         enum aarch64_insn_register reg, int shift, enum aarch64_insn_variant variant,
                                         enum aarch64_insn_adsb_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_ADSB_ADD:
        insn = aarch64_insn_get_add_value();
        break;
    case AARCH64_INSN_ADSB_SUB:
        insn = aarch64_insn_get_sub_value();
        break;
    case AARCH64_INSN_ADSB_ADD_SETFLAGS:
        insn = aarch64_insn_get_adds_value();
        break;
    case AARCH64_INSN_ADSB_SUB_SETFLAGS:
        insn = aarch64_insn_get_subs_value();
        break;
    default:
        fprintf(stdout, "%s: unknown add/sub encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        if (shift & ~(SZ_32 - 1)) {
            fprintf(stdout, "%s: invalid shift encoding %d\n", __func__, shift);
            return AARCH64_BREAK_FAULT;
        }
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        if (shift & ~(SZ_64 - 1)) {
            fprintf(stdout, "%s: invalid shift encoding %d\n", __func__, shift);
            return AARCH64_BREAK_FAULT;
        }
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, reg);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_6, insn, shift);
}

u32 aarch64_insn_gen_data1(enum aarch64_insn_register dst, enum aarch64_insn_register src,
                           enum aarch64_insn_variant variant, enum aarch64_insn_data1_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_DATA1_REVERSE_16:
        insn = aarch64_insn_get_rev16_value();
        break;
    case AARCH64_INSN_DATA1_REVERSE_32:
        insn = aarch64_insn_get_rev32_value();
        break;
    case AARCH64_INSN_DATA1_REVERSE_64:
        if (variant != AARCH64_INSN_VARIANT_64BIT) {
            fprintf(stdout, "%s: invalid variant for reverse64 %d\n", __func__, variant);
            return AARCH64_BREAK_FAULT;
        }
        insn = aarch64_insn_get_rev64_value();
        break;
    default:
        fprintf(stdout, "%s: unknown data1 encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);
}

u32 aarch64_insn_gen_data2(enum aarch64_insn_register dst, enum aarch64_insn_register src,
                           enum aarch64_insn_register reg, enum aarch64_insn_variant variant,
                           enum aarch64_insn_data2_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_DATA2_UDIV:
        insn = aarch64_insn_get_udiv_value();
        break;
    case AARCH64_INSN_DATA2_SDIV:
        insn = aarch64_insn_get_sdiv_value();
        break;
    case AARCH64_INSN_DATA2_LSLV:
        insn = aarch64_insn_get_lslv_value();
        break;
    case AARCH64_INSN_DATA2_LSRV:
        insn = aarch64_insn_get_lsrv_value();
        break;
    case AARCH64_INSN_DATA2_ASRV:
        insn = aarch64_insn_get_asrv_value();
        break;
    case AARCH64_INSN_DATA2_RORV:
        insn = aarch64_insn_get_rorv_value();
        break;
    default:
        fprintf(stdout, "%s: unknown data2 encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);

    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, reg);
}

u32 aarch64_insn_gen_data3(enum aarch64_insn_register dst, enum aarch64_insn_register src,
                           enum aarch64_insn_register reg1, enum aarch64_insn_register reg2,
                           enum aarch64_insn_variant variant, enum aarch64_insn_data3_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_DATA3_MADD:
        insn = aarch64_insn_get_madd_value();
        break;
    case AARCH64_INSN_DATA3_MSUB:
        insn = aarch64_insn_get_msub_value();
        break;
    default:
        fprintf(stdout, "%s: unknown data3 encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RA, insn, src);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, reg1);

    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, reg2);
}

u32 aarch64_insn_gen_logical_shifted_reg(enum aarch64_insn_register dst, enum aarch64_insn_register src,
                                         enum aarch64_insn_register reg, int shift, enum aarch64_insn_variant variant,
                                         enum aarch64_insn_logic_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_LOGIC_AND:
        insn = aarch64_insn_get_and_value();
        break;
    case AARCH64_INSN_LOGIC_BIC:
        insn = aarch64_insn_get_bic_value();
        break;
    case AARCH64_INSN_LOGIC_ORR:
        insn = aarch64_insn_get_orr_value();
        break;
    case AARCH64_INSN_LOGIC_ORN:
        insn = aarch64_insn_get_orn_value();
        break;
    case AARCH64_INSN_LOGIC_EOR:
        insn = aarch64_insn_get_eor_value();
        break;
    case AARCH64_INSN_LOGIC_EON:
        insn = aarch64_insn_get_eon_value();
        break;
    case AARCH64_INSN_LOGIC_AND_SETFLAGS:
        insn = aarch64_insn_get_ands_value();
        break;
    case AARCH64_INSN_LOGIC_BIC_SETFLAGS:
        insn = aarch64_insn_get_bics_value();
        break;
    default:
        fprintf(stdout, "%s: unknown logical encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        if (shift & ~(SZ_32 - 1)) {
            fprintf(stdout, "%s: invalid shift encoding %d\n", __func__, shift);
            return AARCH64_BREAK_FAULT;
        }
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        if (shift & ~(SZ_64 - 1)) {
            fprintf(stdout, "%s: invalid shift encoding %d\n", __func__, shift);
            return AARCH64_BREAK_FAULT;
        }
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, reg);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_6, insn, shift);
}

/*
 * Decode the imm field of a branch, and return the byte offset as a
 * signed value (so it can be used when computing a new branch
 * target).
 */
s32 aarch64_get_branch_offset(u32 insn)
{
    s32 imm;

    if (aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn)) {
        imm = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_26, insn);
        return (imm << 6) >> 4;
    }

    if (aarch64_insn_is_cbz(insn) || aarch64_insn_is_cbnz(insn) || aarch64_insn_is_bcond(insn)) {
        imm = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_19, insn);
        return (imm << 13) >> 11;
    }

    if (aarch64_insn_is_tbz(insn) || aarch64_insn_is_tbnz(insn)) {
        imm = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_14, insn);
        return (imm << 18) >> 16;
    }

    /* Unhandled instruction */
    BUG();
}

/*
 * Encode the displacement of a branch in the imm field and return the
 * updated instruction.
 */
u32 aarch64_set_branch_offset(u32 insn, s32 offset)
{
    if (aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn))
        return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_26, insn, offset >> 2);

    if (aarch64_insn_is_cbz(insn) || aarch64_insn_is_cbnz(insn) || aarch64_insn_is_bcond(insn))
        return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_19, insn, offset >> 2);

    if (aarch64_insn_is_tbz(insn) || aarch64_insn_is_tbnz(insn))
        return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_14, insn, offset >> 2);

    /* Unhandled instruction */
    BUG();
}

s32 aarch64_insn_adrp_get_offset(u32 insn)
{
    BUG_ON(!aarch64_insn_is_adrp(insn));
    return aarch64_insn_decode_immediate(AARCH64_INSN_IMM_ADR, insn) << 12;
}

u32 aarch64_insn_adrp_set_offset(u32 insn, s32 offset)
{
    BUG_ON(!aarch64_insn_is_adrp(insn));
    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_ADR, insn, offset >> 12);
}

/*
 * Extract the Op/CR data from a msr/mrs instruction.
 */
u32 aarch64_insn_extract_system_reg(u32 insn)
{
    return (insn & 0x1FFFE0) >> 5;
}

bool aarch32_insn_is_wide(u32 insn)
{
    return insn >= 0xe800;
}

/*
 * Macros/defines for extracting register numbers from instruction.
 */
u32 aarch32_insn_extract_reg_num(u32 insn, int offset)
{
    return (insn & (0xf << offset)) >> offset;
}

#define OPC2_MASK 0x7
#define OPC2_OFFSET 5
u32 aarch32_insn_mcr_extract_opc2(u32 insn)
{
    return (insn & (OPC2_MASK << OPC2_OFFSET)) >> OPC2_OFFSET;
}

#define CRM_MASK 0xf
u32 aarch32_insn_mcr_extract_crm(u32 insn)
{
    return insn & CRM_MASK;
}

static bool __check_eq(uint64_t pstate)
{
    return (pstate & PSR_Z_BIT) != 0;
}

static bool __check_ne(uint64_t pstate)
{
    return (pstate & PSR_Z_BIT) == 0;
}

static bool __check_cs(uint64_t pstate)
{
    return (pstate & PSR_C_BIT) != 0;
}

static bool __check_cc(uint64_t pstate)
{
    return (pstate & PSR_C_BIT) == 0;
}

static bool __check_mi(uint64_t pstate)
{
    return (pstate & PSR_N_BIT) != 0;
}

static bool __check_pl(uint64_t pstate)
{
    return (pstate & PSR_N_BIT) == 0;
}

static bool __check_vs(uint64_t pstate)
{
    return (pstate & PSR_V_BIT) != 0;
}

static bool __check_vc(uint64_t pstate)
{
    return (pstate & PSR_V_BIT) == 0;
}

static bool __check_hi(uint64_t pstate)
{
    pstate &= ~(pstate >> 1); /* PSR_C_BIT &= ~PSR_Z_BIT */
    return (pstate & PSR_C_BIT) != 0;
}

static bool __check_ls(uint64_t pstate)
{
    pstate &= ~(pstate >> 1); /* PSR_C_BIT &= ~PSR_Z_BIT */
    return (pstate & PSR_C_BIT) == 0;
}

static bool __check_ge(uint64_t pstate)
{
    pstate ^= (pstate << 3); /* PSR_N_BIT ^= PSR_V_BIT */
    return (pstate & PSR_N_BIT) == 0;
}

static bool __check_lt(uint64_t pstate)
{
    pstate ^= (pstate << 3); /* PSR_N_BIT ^= PSR_V_BIT */
    return (pstate & PSR_N_BIT) != 0;
}

static bool __check_gt(uint64_t pstate)
{
    /*PSR_N_BIT ^= PSR_V_BIT */
    uint64_t temp = pstate ^ (pstate << 3);

    temp |= (pstate << 1); /*PSR_N_BIT |= PSR_Z_BIT */
    return (temp & PSR_N_BIT) == 0;
}

static bool __check_le(uint64_t pstate)
{
    /*PSR_N_BIT ^= PSR_V_BIT */
    uint64_t temp = pstate ^ (pstate << 3);

    temp |= (pstate << 1); /*PSR_N_BIT |= PSR_Z_BIT */
    return (temp & PSR_N_BIT) != 0;
}

static bool __check_al(uint64_t pstate)
{
    return true;
}

/*
 * Note that the ARMv8 ARM calls condition code 0b1111 "nv", but states that
 * it behaves identically to 0b1110 ("al").
 */
pstate_check_t *const aarch32_opcode_cond_checks[16] = { __check_eq, __check_ne, __check_cs, __check_cc,
                                                         __check_mi, __check_pl, __check_vs, __check_vc,
                                                         __check_hi, __check_ls, __check_ge, __check_lt,
                                                         __check_gt, __check_le, __check_al, __check_al };

static bool range_of_ones(u64 val)
{
    /* Doesn't handle full ones or full zeroes */
    u64 sval = val >> __ffs64(val);

    /* One of Sean Eron Anderson's bithack tricks */
    return ((sval + 1) & (sval)) == 0;
}

static u32 aarch64_encode_immediate(u64 imm, enum aarch64_insn_variant variant, u32 insn)
{
    uint32_t immr, imms, n, ones, ror, esz, tmp;
    u64 mask = ~0UL;

    /* Can't encode full zeroes or full ones */
    if (!imm || !~imm) return AARCH64_BREAK_FAULT;

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        if (upper_32_bits(imm)) return AARCH64_BREAK_FAULT;
        esz = 32;
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        esz = 64;
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    /*
	 * Inverse of Replicate(). Try to spot a repeating pattern
	 * with a pow2 stride.
	 */
    for (tmp = esz / 2; tmp >= 2; tmp /= 2) {
        u64 emask = BIT(tmp) - 1;

        if ((imm & emask) != ((imm >> tmp) & emask)) break;

        esz = tmp;
        mask = emask;
    }

    /* N is only set if we're encoding a 64bit value */
    n = esz == 64;

    /* Trim imm to the element size */
    imm &= mask;

    /* That's how many ones we need to encode */
    ones = hweight64(imm);

    /*
	 * imms is set to (ones - 1), prefixed with a string of ones
	 * and a zero if they fit. Cap it to 6 bits.
	 */
    imms = ones - 1;
    imms |= 0xf << ffs(esz);
    imms &= BIT(6) - 1;

    /* Compute the rotation */
    if (range_of_ones(imm)) {
        /*
		 * Pattern: 0..01..10..0
		 *
		 * Compute how many rotate we need to align it right
		 */
        ror = __ffs64(imm);
    } else {
        /*
		 * Pattern: 0..01..10..01..1
		 *
		 * Fill the unused top bits with ones, and check if
		 * the result is a valid immediate (all ones with a
		 * contiguous ranges of zeroes).
		 */
        imm |= ~mask;
        if (!range_of_ones(~imm)) return AARCH64_BREAK_FAULT;

        /*
		 * Compute the rotation to get a continuous set of
		 * ones, with the first bit set at position 0
		 */
        ror = fls(~imm);
    }

    /*
	 * immr is the number of bits we need to rotate back to the
	 * original set of ones. Note that this is relative to the
	 * element size...
	 */
    immr = (esz - ror) % esz;

    insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_N, insn, n);
    insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_R, insn, immr);
    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_S, insn, imms);
}

u32 aarch64_insn_gen_logical_immediate(enum aarch64_insn_logic_type type, enum aarch64_insn_variant variant,
                                       enum aarch64_insn_register Rn, enum aarch64_insn_register Rd, u64 imm)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_LOGIC_AND:
        insn = aarch64_insn_get_and_imm_value();
        break;
    case AARCH64_INSN_LOGIC_ORR:
        insn = aarch64_insn_get_orr_imm_value();
        break;
    case AARCH64_INSN_LOGIC_EOR:
        insn = aarch64_insn_get_eor_imm_value();
        break;
    case AARCH64_INSN_LOGIC_AND_SETFLAGS:
        insn = aarch64_insn_get_ands_imm_value();
        break;
    default:
        fprintf(stdout, "%s: unknown logical encoding %d\n", __func__, type);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, Rd);
    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, Rn);
    return aarch64_encode_immediate(imm, variant, insn);
}

u32 aarch64_insn_gen_extr(enum aarch64_insn_variant variant, enum aarch64_insn_register Rm,
                          enum aarch64_insn_register Rn, enum aarch64_insn_register Rd, u8 lsb)
{
    u32 insn;

    insn = aarch64_insn_get_extr_value();

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        if (lsb > 31) return AARCH64_BREAK_FAULT;
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        if (lsb > 63) return AARCH64_BREAK_FAULT;
        insn |= AARCH64_INSN_SF_BIT;
        insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_N, insn, 1);
        break;
    default:
        fprintf(stdout, "%s: unknown variant encoding %d\n", __func__, variant);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_S, insn, lsb);
    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, Rd);
    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, Rn);
    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, Rm);
}