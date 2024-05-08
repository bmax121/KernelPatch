/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <error.h>

#include "../banner"
#include "uapi/scdefs.h"
#include "kpatch.h"
#include "su.h"
#include "kpm.h"

#ifdef ANDROID
#include "android/sumgr.h"
#include "android/android_user.h"
#endif

char program_name[128] = { '\0' };
const char *key = NULL;

static void usage(int status)
{
    if (status != EXIT_SUCCESS) {
        fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
    } else {
        fprintf(stdout, "\nKernelPatch userspace cli.\n");
        fprintf(stdout, KERNEL_PATCH_BANNER);
        fprintf(stdout,
                " \n"
                "Options: \n"
                "%s -h, --help       Print this help message. \n"
                "%s -v, --version    Print version. \n"
                "\n",
                program_name, program_name);
        fprintf(stdout, "Usage: %s <COMMAND> [-h, --help] [COMMAND_ARGS]...\n", program_name);
        fprintf(stdout,
                "\n"
                "Commands:\n"
                "hello       If KernelPatch installed, '%s' will echoed.\n"
                "kpver       Print KernelPatch version.\n"
                "kver        Print Kernel version.\n"
                "key         Manager the superkey.\n"
                "su          KernelPatch Substitute User.\n"
                "kpm         KernelPatch Module manager.\n"
#ifdef ANDROID
                "sumgr       SU permission manager for Android.\n"
#endif
                "\n",
                SUPERCALL_HELLO_ECHO);
    }
    exit(status);
}

// todo: refactor
int main(int argc, char **argv)
{
    strcat(program_name, argv[0]);

    if (argc == 1) usage(EXIT_FAILURE);

    key = argv[1];
    strcat(program_name, " <SUPERKEY>");

    if (argc == 2) {
        if (!strcmp(argv[1], "-v") || !(strcmp(argv[1], "--version"))) {
            fprintf(stdout, "%x\n", version());
        } else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            usage(EXIT_SUCCESS);
        } else {
            usage(EXIT_FAILURE);
        }
        return 0;
    }

    if (!key[0]) error(-EINVAL, 0, "invalid superkey");

    if (strnlen(key, SUPERCALL_KEY_MAX_LEN) >= SUPERCALL_KEY_MAX_LEN) error(-EINVAL, 0, "superkey too long");

    const char *scmd = argv[2];
    int cmd = -1;

    struct
    {
        const char *scmd;
        int cmd;
    } cmd_arr[] = {
        { "hello", SUPERCALL_HELLO },
        { "kpver", SUPERCALL_KERNELPATCH_VER },
        { "kver", SUPERCALL_KERNEL_VER },
        { "key", 'K' },
        { "su", 's' },
        { "kpm", 'k' },

        { "bootlog", 'l' },
        { "panic", '.' },
        { "test", 't' },

        { "--help", 'h' },
        { "-h", 'h' },
        { "--version", 'v' },
        { "-v", 'v' },
#ifdef ANDROID
        { "sumgr", 'm' },
        { "android_user", 'a' },
#endif
    };

    for (int i = 0; i < sizeof(cmd_arr) / sizeof(cmd_arr[0]); i++) {
        if (strcmp(scmd, cmd_arr[i].scmd)) continue;
        cmd = cmd_arr[i].cmd;
        break;
    }

    if (cmd < 0) error(-EINVAL, 0, "Invalid command: %s!\n", scmd);

    switch (cmd) {
    case SUPERCALL_HELLO:
        hello(key);
        return 0;
    case SUPERCALL_KERNELPATCH_VER:
        kpv(key);
        return 0;
    case SUPERCALL_KERNEL_VER:
        kv(key);
        return 0;
    case 's':
        strcat(program_name, " su");
        return su_main(argc - 2, argv + 2);
    case 'K':
        strcat(program_name, " key");
        return skey_main(argc - 2, argv + 2);
    case 'k':
        strcat(program_name, " kpm");
        return kpm_main(argc - 2, argv + 2);
    case 'l':
        bootlog(key);
        break;
    case '.':
        panic(key);
        break;
    case 't':
        __test(key);
        break;

    case 'h':
        usage(EXIT_SUCCESS);
        break;
    case 'v':
        fprintf(stdout, "%x\n", version());
        break;

#ifdef ANDROID
    case 'm':
        strcat(program_name, " sumgr");
        return sumgr_main(argc - 2, argv + 2);
    case 'a':
        return android_user(argc - 2, argv + 2);
#endif

    default:
        fprintf(stderr, "Invalid command: %s!\n", scmd);
        return -EINVAL;
    }

    return 0;
}
