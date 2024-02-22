/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_PIDMEM_H_
#define _KP_PIDMEM_H_

#include <ktypes.h>

phys_addr_t pid_virt_to_phys(pid_t pid, uintptr_t vaddr);

// void *pid_map_mem(pid_t pid, void *mem, size_t size, )

#endif
