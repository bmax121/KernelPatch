/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "setup.h"
#include "../version"

setup_header_t header __section(.setup.header) = { .magic = KP_MAGIC,
                                                   .kp_version.major = MAJOR,
                                                   .kp_version.minor = MINOR,
                                                   .kp_version.patch = PATCH,
                                                   .config_flags = 0
#ifdef ANDROID
                                                                   | CONFIG_ANDROID
#endif
#ifdef DEBUG
                                                                   | CONFIG_DEBUG
#endif
                                                   ,
                                                   .compile_time = __TIME__ " " __DATE__ };

setup_preset_t setup_preset __section(.setup.preset) = { 0 };

struct
{
    uint8_t fp[STACK_SIZE];
    uint8_t sp[0];
} stack __section(.setup.data) __aligned(16);
