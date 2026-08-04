// SPDX-License-Identifier: GPL-2.0-or-later
/* Reuse KernelPatch's ARM64 relocation and hook-chain engine. */
#include <linux/compiler.h>
#include <linux/types.h>

#ifndef __noinline
#define __noinline noinline
#endif

/* The original kpimg linker script provides _transit*_end and copies each
 * transit function into hook memory. Linux modules have no such linker
 * markers, so emit a small absolute branch to the resident LKM function. */
#define KP_HOOK_EXTERNAL_CHAIN_PREPARE

#include "../../kernel/base/hook.c"

static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno)
{
	uint64_t target;
	hook_chain_t *chain = local_container_of(transit, hook_chain_t, transit);

	if (argno < 0 || argno > 12)
		return -HOOK_BAD_ADDRESS;
	if (argno == 0)
		target = (uint64_t)_transit0;
	else if (argno <= 4)
		target = (uint64_t)_transit4;
	else if (argno <= 8)
		target = (uint64_t)_transit8;
	else
		target = (uint64_t)_transit12;

	transit[0] = ARM64_BTI_JC;
	transit[1] = 0x58000070; /* LDR X16, #12 */
	transit[2] = 0x14000004; /* B #16 */
	transit[3] = ARM64_NOP;
	transit[4] = (uint64_t)chain;
	transit[5] = (uint64_t)chain >> 32;
	return branch_absolute(&transit[6], target) ? HOOK_NO_ERR : -HOOK_TRANSIT_NO_MEM;
}
