/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "../version"

#include "preset.h"
#include "image.h"
#include "order.h"
#include "kallsym.h"
#include "patch.h"
#include "common.h"
#include "kpm.h"

uint32_t version = 0;
const char *program_name = NULL;

void print_usage(char **argv)
{
    char *c =
        "Kernel Image Patch Tools. v%x\n"
        "\n"
        "Usage: %s COMMAND [Options...]\n"
        "\n"
        "COMMAND:\n"
        "  -h, --help                   Print this message.\n"
        "  -v, --version                Print version number. Print kpimg version if -k specified.\n"

        "  -p, --patch                  Patch or Update patch of kernel image(-i) with specified kpimg(-k) and superkey(-s).\n"
        "  -u, --unpatch                Unpatch patched kernel image(-i).\n"
        "  -r, --resetkey               Reset superkey of patched image(-i).\n"
        "  -d, --dump                   Dump kallsyms infomations of kernel image(-i).\n"
        "  -l, --list                   Print all patch informations of kernel image if -i specified.\n"
        "                               Print KPM informations if -M specified.\n"
        "                               Print KernelPatch image informations if -k specified.\n"

        "Options:\n"
        "  -i, --image PATH             Kernel image path.\n"
        "  -k, --kpimg PATH             KernelPatch image path.\n"
        "  -o, --out PATH               Patched image path.\n"
        "  -K, --kpatch PATH            Embed kpatch executable binary into patches.\n"

        "  -E, --embed-kpm PATH         Embed KPM into patches.\n"
        "  -A, --embed-kpm-args ARGS    Arguments will be passed to previous KPM(-E).\n"
        "  -D, --detach-kpm NAME        Detach embeded KPM from patches.\n"
        "  -M, --kpm PATH               Specify KPM path.\n"
        "  -a  --addition KEY=VALUE     Add additional information.\n"
        "\n";
    fprintf(stdout, c, version, program_name);
}

int main(int argc, char *argv[])
{
    version = (MAJOR << 16) + (MINOR << 8) + PATCH;
    program_name = argv[0];

    struct option longopts[] = { { "help", no_argument, NULL, 'h' },
                                 { "version", no_argument, NULL, 'v' },

                                 { "patch", no_argument, NULL, 'p' },
                                 { "unpatch", no_argument, NULL, 'u' },
                                 { "resetkey", no_argument, NULL, 'r' },
                                 { "dump", no_argument, NULL, 'd' },
                                 { "list", no_argument, NULL, 'l' },

                                 { "image", required_argument, NULL, 'i' },
                                 { "kpimg", required_argument, NULL, 'k' },
                                 { "skey", required_argument, NULL, 's' },
                                 { "out", required_argument, NULL, 'o' },
                                 { "kpatch", required_argument, NULL, 'K' },

                                 { "embed-kpm", required_argument, NULL, 'E' },
                                 { "embed-kpm-args", required_argument, NULL, 'A' },
                                 { "detach-kpm", required_argument, NULL, 'D' },
                                 { "kpm", required_argument, NULL, 'M' },
                                 { "addition", required_argument, NULL, 'a' },
                                 { 0, 0, 0, 0 } };
    char *optstr = "hvpurdli:s:k:o:K:E:A:D:M:a:";

    char *kimg_path = NULL;
    char *kpimg_path = NULL;
    char *out_path = NULL;
    char *superkey = NULL;
    char *kpatch_path = NULL;

    int embed_kpm_num = 0;
    char *embed_kpms_path[EXTRA_ITEM_MAX_NUM] = { 0 };
    char *embed_kpms_args[EXTRA_ITEM_MAX_NUM] = { 0 };

    int detach_kpm_num = 0;
    char *detach_kpms_name[EXTRA_ITEM_MAX_NUM] = { 0 };

    int additional_num = 0;
    char *additional[16] = { 0 };

    char *alone_kpm_path = NULL;

    char cmd = '\0';
    int opt = -1;
    int opt_index = -1;

    while ((opt = getopt_long(argc, argv, optstr, longopts, &opt_index)) != -1) {
        switch (opt) {
        case 'h':
        case 'v':
        case 'p':
        case 'u':
        case 'r':
        case 'd':
        case 'l':
            cmd = opt;
            break;
        case 'i':
            kimg_path = optarg;
            break;
        case 'k':
            kpimg_path = optarg;
            break;
        case 's':
            superkey = optarg;
            break;
        case 'o':
            out_path = optarg;
            break;
        case 'K':
            kpatch_path = optarg;
            break;
        case 'E':
            embed_kpms_path[embed_kpm_num++] = optarg;
            break;
        case 'A':
            embed_kpms_args[embed_kpm_num - 1] = optarg;
            break;
        case 'D':
            detach_kpms_name[detach_kpm_num++] = optarg;
            break;
        case 'M':
            alone_kpm_path = optarg;
            break;
        case 'a':
            additional[additional_num++] = optarg;
            break;
        default:
            break;
        }
    }
    int ret = 0;

    if (cmd == 'h') {
        print_usage(argv);
    } else if (cmd == 'v') {
        if (kpimg_path)
            fprintf(stdout, "%x\n", get_kpimg_version(kpimg_path));
        else
            fprintf(stdout, "%x\n", version);
    } else if (cmd == 'p') {
        ret = patch_update_img(kimg_path, kpimg_path, out_path, superkey, (const char **)embed_kpms_path,
                               (const char **)embed_kpms_args, (const char **)detach_kpms_name,
                               (const char **)additional);
    } else if (cmd == 'd') {
        ret = dump_kallsym(kimg_path);
    } else if (cmd == 'u') {
        ret = unpatch_img(kimg_path, out_path);
    } else if (cmd == 'r') {
        ret = reset_key(kimg_path, out_path, superkey);
    } else if (cmd == 'l') {
        if (kimg_path) print_image_patch_info_path(kimg_path);
        if (alone_kpm_path) print_kpm_info_path(alone_kpm_path);
        if (kpimg_path) print_kp_image_info_path(kpimg_path);
    }

    else {
        print_usage(argv);
    }
    return ret;
}
