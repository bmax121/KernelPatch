/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_KPM_RELO_H_
#define _KP_LKM_KPM_RELO_H_

#include <linux/elf.h>
#include <linux/types.h>

struct kp_module;

int kp_apply_relocate(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex,
		      unsigned int relsec, struct kp_module *me);
int kp_apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex,
			  unsigned int relsec, struct kp_module *me);

#endif /* _KP_LKM_KPM_RELO_H_ */
