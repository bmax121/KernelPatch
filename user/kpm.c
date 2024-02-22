/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <error.h>

#include "kpm.h"
#include "supercall.h"

int kpm_load(const char *key, const char *path, const char *args)
{
    int rc = sc_kpm_load(key, path, args, 0);
    return rc;
}

int kpm_control(const char *key, const char *name, const char *ctl_args)
{
    char buf[4096] = { '\0' };
    int rc = sc_kpm_control(key, name, ctl_args, buf, sizeof(buf));
    fprintf(stdout, "%s", buf);
    return rc;
}

int kpm_unload(const char *key, const char *name)
{
    int rc = sc_kpm_unload(key, name, 0);
    return rc;
}

int kpm_nums(const char *key)
{
    int nums = sc_kpm_nums(key);
    fprintf(stdout, "%d\n", nums);
    return 0;
}

int kpm_list(const char *key)
{
    char buf[4096];
    int rc = sc_kpm_list(key, buf, sizeof(buf));
    if (rc > 0) {
        fprintf(stdout, "%s", buf);
        return 0;
    }
    return rc;
}

int kpm_info(const char *key, const char *name)
{
    char buf[4096];
    int rc = sc_kpm_info(key, name, buf, sizeof(buf));
    if (rc > 0) {
        fprintf(stdout, "%s", buf);
        return 0;
    }
    return rc;
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
                        "KernelPatch Module command set.\n"
                        "\n"
                        "help                           Print this help message. \n"
                        "load <KPM_PATH> [KPM_ARGS]     Load KernelPatch Module with KPM_PATH and KPM_ARGS.\n"
                        "ctl0 <KPM_NAME> <CTL_ARGS>     Control KernelPatch Module named KPM_PATH with CTL_ARGS.\n"
                        "unload <KPM_NAME>              Unload KernelPatch Module named KPM_NAME.\n"
                        "num                            Get the number of modules that have been loaded.\n"
                        "list                           List names of all loaded modules.\n"
                        "info <KPM_NAME>                Get detailed information about module named KPM_NAME.\n"
                        "");
    }
    exit(status);
}

int kpm_main(int argc, char **argv)
{
    if (argc < 2) usage(EXIT_FAILURE);

    const char *scmd = argv[1];
    int cmd = -1;

    struct
    {
        const char *scmd;
        int cmd;
    } cmd_arr[] = {
        { "load", SUPERCALL_KPM_LOAD },
        { "ctl0", SUPERCALL_KPM_CONTROL },
        { "unload", SUPERCALL_KPM_UNLOAD },
        { "num", SUPERCALL_KPM_NUMS },
        { "list", SUPERCALL_KPM_LIST },
        { "info", SUPERCALL_KPM_INFO },
        { "help", 0 },
    };

    for (int i = 0; i < sizeof(cmd_arr) / sizeof(cmd_arr[0]); i++) {
        if (strcmp(scmd, cmd_arr[i].scmd)) continue;
        cmd = cmd_arr[i].cmd;
        break;
    }

    if (cmd < 0) usage(EXIT_FAILURE);

    const char *path = NULL;
    const char *mod_args = NULL;
    const char *ctl_args = NULL;
    const char *name = NULL;

    switch (cmd) {
    case SUPERCALL_KPM_LOAD:
        if (argc < 3) error(-EINVAL, 0, "module path does not exist");
        path = argv[2];
        mod_args = argc < 4 ? NULL : argv[3];
        return kpm_load(key, path, mod_args);
    case SUPERCALL_KPM_CONTROL:
        if (argc < 3) error(-EINVAL, 0, "module name does not exist");
        if (argc < 4) error(-EINVAL, 0, "control argument does not exist");
        name = argv[2];
        ctl_args = argv[3];
        return kpm_control(key, name, ctl_args);
    case SUPERCALL_KPM_UNLOAD:
        if (argc < 3) error(-EINVAL, 0, "module name does not exist");
        name = argv[2];
        return kpm_unload(key, name);
    case SUPERCALL_KPM_NUMS:
        return kpm_nums(key);
    case SUPERCALL_KPM_LIST:
        return kpm_list(key);
    case SUPERCALL_KPM_INFO:
        if (argc < 3) error(-EINVAL, 0, "module name does not exist");
        name = argv[2];
        return kpm_info(key, name);
    case 0:
        usage(EXIT_SUCCESS);
    default:
        usage(EXIT_FAILURE);
    }

    return 0;
}