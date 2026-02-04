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
#include "bootimg.h"
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
        "Kernel Image Patch Tools. version: %x\n"
        "\n"
        "Usage: %s COMMAND [Options...]\n"
        "\n"
        "COMMAND:\n"
        "  -h, --help                       Print this message.\n"
        "  -v, --version                    Print version number. Print kpimg version if -k specified.\n"

        "  -p, --patch                      Patch or Update patch of kernel image(-i) with specified kpimg(-k) and superkey(-s).\n"
        "  -u, --unpatch                    Unpatch patched kernel image(-i).\n"
        "  -r, --reset-skey                 Reset superkey of patched image(-i).\n"
        "  -d, --dump                       Dump kallsyms infomations of kernel image(-i).\n"
        "  -f, --flag                       Dump ikconfig infomations of kernel image(-i).\n"
        "  -l, --list                       Print all patch informations of kernel image if (-i) specified.\n"
        "                                   Print extra item informations if (-M) specified.\n"
        "                                   Print KernelPatch image informations if (-k) specified.\n"
        "Unpack kernel: unpack <boot.img>\n  Repack Kernel: repack <boot.img>\n"
        "Options:\n"
        "  -i, --image PATH                 Kernel image path.\n"
        "  -k, --kpimg PATH                 KernelPatch image path.\n"
        "  -s, --skey KEY                   Set the superkey and save it directly in the boot.img.\n"
        "  -S, --root-skey KEY              Set the root-superkey useing hash verification, and the superkey can be changed dynamically.\n"
        "  -o, --out PATH                   Patched image path.\n"
        "  -a  --addition KEY=VALUE         Add additional information.\n"

        "  -K, --kpatch PATH                Embed kpatch executable binary into patches.\n"

        "  -M, --embed-extra-path PATH      Embed new extra item.\n"
        "  -E, --embeded-extra-name NAME    Preserve and modifiy embedded extra item.\n"

        "  -T, --extra-type TYPE            Set type of previous extra item.\n"
        "  -N, --extra-name NAME            Set name of previous extra item.\n"
        "  -V, --extra-event EVENT          Set trigger event of previous extra item.\n"
        "  -A, --extra-args ARGS            Set arguments of previous extra item.\n"
        "  -D, --extra-detach               Detach previous extra item from patches.\n"
        "\n";
    fprintf(stdout, c, version, program_name);
}

int main(int argc, char *argv[])
{
    version = (MAJOR << 16) + (MINOR << 8) + PATCH;
    program_name = argv[0];
    if (argc > 2){
        
        if (strcmp(argv[1], "unpack") == 0) {
            set_log_enable(true);
            return extract_kernel(argv[2]);
        }
        if (strcmp(argv[1], "unpacknolog") == 0) {
            return extract_kernel(argv[2]);
        } 
        else if (strcmp(argv[1], "repack") == 0) {
            set_log_enable(true);
            return repack_bootimg(argv[2], "kernel", "new-boot.img");
        } 
    }
    struct option longopts[] = { { "help", no_argument, NULL, 'h' },
                                 { "version", no_argument, NULL, 'v' },

                                 { "patch", no_argument, NULL, 'p' },
                                 { "unpatch", no_argument, NULL, 'u' },
                                 { "resetkey", no_argument, NULL, 'r' },
                                 { "dump", no_argument, NULL, 'd' },
                                 { "flag", no_argument, NULL, 'f' },
                                 { "list", no_argument, NULL, 'l' },

                                 { "image", required_argument, NULL, 'i' },
                                 { "kpimg", required_argument, NULL, 'k' },
                                 { "skey", required_argument, NULL, 's' },
                                 { "root-skey", required_argument, NULL, 'S' },
                                 { "out", required_argument, NULL, 'o' },
                                 { "addition", required_argument, NULL, 'a' },

                                 { "embed-extra-path", required_argument, NULL, 'M' },
                                 { "embeded-extra-name", required_argument, NULL, 'E' },
                                 { "extra-type", required_argument, NULL, 'T' },
                                 { "extra-name", required_argument, NULL, 'N' },
                                 { "extra-event", required_argument, NULL, 'V' },
                                 { "extra-args", required_argument, NULL, 'A' },
                                 { 0, 0, 0, 0 } };
    char *optstr = "hvpurdfli:s:S:k:o:a:M:E:T:N:V:A:";

    char *kimg_path = NULL;
    char *kpimg_path = NULL;
    char *out_path = NULL;
    char *superkey = NULL;
    bool root_skey = false;

    int additional_num = 0;
    const char *additional[16] = { 0 };

    int extra_config_num = 0;
    extra_config_t *extra_configs = (extra_config_t *)malloc(sizeof(extra_config_t) * EXTRA_ITEM_MAX_NUM);
    memset(extra_configs, 0, sizeof(extra_config_t) * EXTRA_ITEM_MAX_NUM);
    extra_config_t *config = NULL;

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
        case 'f':
        case 'l':
            cmd = opt;
            break;
        case 'i':
            kimg_path = optarg;
            break;
        case 'k':
            kpimg_path = optarg;
            break;
        case 'S':
            root_skey = true;
        case 's':
            superkey = optarg;
            break;
        case 'o':
            out_path = optarg;
            break;
        case 'a':
            additional[additional_num++] = optarg;
            break;
        case 'M':
            config = &extra_configs[extra_config_num++];
            config->is_path = true;
            config->path = optarg;
            break;
        case 'E':
            config = &extra_configs[extra_config_num++];
            config->is_path = false;
            config->name = optarg;
            break;
        case 'T':
            config->extra_type = extra_str_type(optarg);
            if (config->extra_type == EXTRA_TYPE_NONE) {
                tools_loge_exit("invalid extra type: %s\n", optarg);
            }
            break;
        case 'V':
            config->set_event = optarg;
            break;
        case 'N':
            config->name = optarg;
            break;
        case 'A':
            config->set_args = optarg;
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
        ret = patch_update_img(kimg_path, kpimg_path, out_path, superkey, root_skey, additional, extra_configs,
                               extra_config_num);
    } else if (cmd == 'd') {
        ret = dump_kallsym(kimg_path);
    } else if (cmd == 'f') {
        ret = dump_ikconfig(kimg_path);
    } else if (cmd == 'u') {
        ret = unpatch_img(kimg_path, out_path);
    } else if (cmd == 'r') {
        ret = reset_key(kimg_path, out_path, superkey);
    } else if (cmd == 'l') {
        if (kimg_path) return print_image_patch_info_path(kimg_path);
        if (config && config->path) return print_kpm_info_path(config->path);
        if (kpimg_path) return print_kp_image_info_path(kpimg_path);
    }

    else {
        print_usage(argv);
    }

    free(extra_configs);

    return ret;
}
