/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_SUPERCALL_AUTH_H_
#define _KP_SUPERCALL_AUTH_H_

/* Include scdefs.h before this file. SU allowlist membership is not administration. */
static inline int kp_supercall_allowed_for_su(long command)
{
    switch (command) {
    case SUPERCALL_HELLO:
    case SUPERCALL_KERNELPATCH_VER:
    case SUPERCALL_KERNEL_VER:
    case SUPERCALL_BUILD_TIME:
    case SUPERCALL_SU:
    case SUPERCALL_SU_PROFILE: /* dispatch must restrict this to the caller's uid */
    case SUPERCALL_SU_GET_PATH:
    case SUPERCALL_SU_GET_SAFEMODE:
        return 1;
    default:
        return 0;
    }
}

#endif
