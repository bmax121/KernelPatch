/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <preset.h>

#include "../../version"

#define __section(name) __attribute__((section(#name)))

setup_header_t x86_header __section(.setup.header) = {
    .magic = KP_MAGIC,
    .kp_version.major = MAJOR,
    .kp_version.minor = MINOR,
    .kp_version.patch = PATCH,
    .config_flags = CONFIG_FLAG_X86_64
#ifdef ANDROID
                    | CONFIG_ANDROID
#endif
#ifdef DEBUG
                    | CONFIG_DEBUG
#endif
    ,
    .compile_time = __TIME__ " " __DATE__,
};

setup_preset_t x86_setup_preset __section(.setup.preset) = { 0 };

/* kpimg_x86_start is defined in x86_start.c */
