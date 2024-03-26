/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "kpatch.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/capability.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <error.h>

#include "supercall.h"

uint32_t version()
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return version_code;
}

void hello(const char *key)
{
    long ret = sc_hello(key);
    if (ret == SUPERCALL_HELLO_MAGIC) {
        fprintf(stdout, "%s\n", SUPERCALL_HELLO_ECHO);
    }
}

void kpv(const char *key)
{
    uint32_t kpv = sc_kp_ver(key);
    fprintf(stdout, "%x\n", kpv);
}

void kv(const char *key)
{
    uint32_t kv = sc_k_ver(key);
    fprintf(stdout, "%x\n", kv);
}

void bootlog(const char *key)
{
    sc_bootlog(key);
}

void panic(const char *key)
{
    sc_panic(key);
}

int __test(const char *key)
{
    // return __sc_test(key, 0, 0, 0);
    return sc_pid_virt_to_phys(key, getpid(), (unsigned long)__test);
}

extern const char program_name[];
extern const char *key;

static void usage(int status)
{
    if (status != EXIT_SUCCESS)
        fprintf(stderr, "Try `%s help' for more information.\n", program_name);
    else {
        printf("Usage: %s <COMMAND> [ARG]...\n\n", program_name);
        fprintf(stdout, ""
                        "KernelPatch SuperKey manager.\n"
                        "\n"
                        "help                           Print this help message. \n"
                        "get                            Print current superkey.\n"
                        "set <SUPERKEY>                 Set current superkey.\n"
                        "rootkey [enable|disable]       Whether to use hash to verify the root superkey.\n"
                        "");
    }
    exit(status);
}

int skey_main(int argc, char **argv)
{
    if (argc < 2) usage(EXIT_FAILURE);

    const char *scmd = argv[1];
    int cmd = -1;

    struct
    {
        const char *scmd;
        int cmd;
    } cmd_arr[] = {
        { "get", SUPERCALL_SKEY_GET },
        { "set", SUPERCALL_SKEY_SET },
        { "rootkey", SUPERCALL_SKEY_ROOT_ENABLE },
        { "help", 0 },
    };

    for (int i = 0; i < sizeof(cmd_arr) / sizeof(cmd_arr[0]); i++) {
        if (strcmp(scmd, cmd_arr[i].scmd)) continue;
        cmd = cmd_arr[i].cmd;
        break;
    }

    if (cmd < 0) usage(EXIT_FAILURE);
    char out_buf[SUPERCALL_KEY_MAX_LEN] = { '\0' };

    switch (cmd) {
    case SUPERCALL_SKEY_GET:
        sc_skey_get(key, out_buf, sizeof(out_buf));
        fprintf(stdout, "%s\n", out_buf);
        break;
    case SUPERCALL_SKEY_SET:
        if (argc < 3) error(-EINVAL, 0, "no new superkey");
        const char *new_key = argv[2];
        return sc_skey_set(key, new_key);
    case SUPERCALL_SKEY_ROOT_ENABLE:
        if (argc < 3) error(-EINVAL, 0, "no enable or disable specified");
        if (!strcmp("enable", argv[2])) {
            sc_skey_root_enable(key, true);
        } else if (!strcmp("disable", argv[2])) {
            sc_skey_root_enable(key, false);
        } else {
            error(-EINVAL, 0, "no enable or disable specified");
        }
        break;
    case 0:
        usage(EXIT_SUCCESS);
    default:
        usage(EXIT_FAILURE);
    }

    return 0;
}