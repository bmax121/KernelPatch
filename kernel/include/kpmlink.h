/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_KPM_LINK_H_
#define _KP_KPM_LINK_H_

/* Kept inside each KPM allocation; no persistent kpimg/preset ABI changes. */
#define KPM_LINK_SLOT_SIZE 32U
#define KPM_LINK_MAX_IMAGE (64U * 1024U * 1024U)
#define KPM_RELOC_ADR_GOT_PAGE 311U
#define KPM_RELOC_LD64_GOT_LO12_NC 312U
#define KPM_RELOC_GOT_LD_PREL19 309U

struct kpm_link_slot {
    unsigned int insn[4];
    unsigned long target;
    unsigned long reserved;
};

struct kpm_link_state {
    unsigned long offset;
    unsigned int capacity;
    unsigned int used;
};

static inline int kpm_link_reserve(struct kpm_link_state *state, unsigned int *size,
                                   unsigned long count)
{
    unsigned long offset = ((unsigned long)*size + 15UL) & ~15UL;
    if (offset > KPM_LINK_MAX_IMAGE || count > (KPM_LINK_MAX_IMAGE - offset) / KPM_LINK_SLOT_SIZE)
        return -1;
    state->offset = offset;
    state->capacity = count;
    state->used = 0;
    *size = offset + count * KPM_LINK_SLOT_SIZE;
    return 0;
}

static inline struct kpm_link_slot *kpm_link_get(struct kpm_link_state *state, void *image,
                                                unsigned long target)
{
    struct kpm_link_slot *slots = (void *)((char *)image + state->offset);
    unsigned int i;
    for (i = 0; i < state->used; i++) {
        if (slots[i].target == target) return &slots[i];
    }
    if (state->used == state->capacity) return 0;
    struct kpm_link_slot *slot = &slots[state->used++];
    slot->insn[0] = 0xd503245fU; /* bti c */
    slot->insn[1] = 0x58000070U; /* ldr x16, .+12 (target at +16) */
    slot->insn[2] = 0xd61f0200U; /* br x16: tail call preserves x30 */
    slot->insn[3] = 0xd503201fU; /* nop */
    slot->target = target;
    slot->reserved = 0;
    return slot;
}

static inline unsigned long kpm_link_plt(struct kpm_link_state *state, void *image,
                                        unsigned long target)
{
    struct kpm_link_slot *slot = kpm_link_get(state, image, target);
    return (unsigned long)slot;
}

static inline unsigned long kpm_link_pointer(struct kpm_link_state *state, void *image,
                                            unsigned long target)
{
    struct kpm_link_slot *slot = kpm_link_get(state, image, target);
    return slot ? (unsigned long)&slot->target : 0;
}

static inline int kpm_link_branch_in_range(unsigned long place, unsigned long target)
{
    long delta = target - place;
    return !(delta & 3L) && delta >= -(1L << 27) && delta < (1L << 27);
}

#endif
