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

#include "../version"

#include "preset.h"
#include "image.h"
#include "order.h"
#include "kallsym.h"
#include "patch.h"
#include "common.h"

static uint32_t version = 0;

static char kimg_path[FILENAME_MAX] = { '\0' };
static char kpimg_path[FILENAME_MAX] = { '\0' };
static char out_path[FILENAME_MAX] = { '\0' };
static char superkey[SUPER_KEY_LEN] = { '\0' };

const char *program_name = NULL;

void print_usage(char **argv)
{
    char *c = "\n%s Kernel Image Patch Tools. "
              "\n"
              "Usage: ./kptools ...\n"
              "  -h, --help\n"
              "    Print this message.\n"
              "\n"
              "  -p, --patch <kernel_image> <--kpimg kpimg> <--skey super_key> [--out image_patched]\n"
              "    Patch kernel_image with kpimg.\n"
              "    If --out is not specified, default ${kernel_image}__patched will be used.\n"
              "    super_key: Authentication key for supercall system call.\n"
              "\n"
              "  -u, --unpatch <patched_kernel_image> [--out image_patched]\n"
              "    Reset superkey of patched_kernel_image to new_super_key.\n"
              "    If --out is not specified, default ${kernel_image}__patched will be used.\n"
              "\n"
              "  -r, --resetkey <patched_kernel_image> <--skey new_super_key> [--out image_patched]\n"
              "    Reset superkey of patched_kernel_image to new_super_key.\n"
              "    If --out is not specified, default ${kernel_image}__patched will be used.\n"
              "\n"
              "  -d, --dump <kernel_image>\n"
              "    Analyze and dump kallsyms infomations of kernel_image to stdout.\n"
              "\n";
    fprintf(stdout, c, argv[0], version);
}

int main(int argc, char *argv[])
{
    version = (MAJOR << 16) + (MINOR << 8) + PATCH;
    fprintf(stdout, "%s version: %x\n", argv[0], version);

    struct option longopts[] = {
        { "version", no_argument, NULL, 'v' },         { "help", no_argument, NULL, 'h' },

        { "patch", required_argument, NULL, 'p' },     { "unpatch", required_argument, NULL, 'u' },
        { "reset_key", required_argument, NULL, 'r' }, { "dump", required_argument, NULL, 'd' },

        { "skey", required_argument, NULL, 's' },      { "out", required_argument, NULL, 'o' },
        { "kpimg", required_argument, NULL, 'k' },     { 0, 0, 0, 0 }
    };
    char *optstr = "vhp:d:o:r:u:k:s:";

    char cmd = '\0';
    int opt = -1;
    int opt_index = -1;
    while ((opt = getopt_long(argc, argv, optstr, longopts, &opt_index)) != -1) {
        switch (opt) {
        case 'v':
            cmd = 'v';
            break;
        case 'h':
            cmd = 'h';
            break;
        case 'p':
        case 'd':
        case 'u':
        case 'r':
            cmd = opt;
            strncpy(kimg_path, optarg, FILENAME_MAX - 1);
            break;
        case 'o':
            strncpy(out_path, optarg, FILENAME_MAX - 1);
            break;
        case 'k':
            strncpy(kpimg_path, optarg, FILENAME_MAX - 1);
            break;
        case 's':
            strncpy(superkey, optarg, SUPER_KEY_LEN);
            break;
        default:
            break;
        }
    }
    int ret = 0;

    if (!strlen(out_path)) {
        strcpy(out_path, kimg_path);
        strcat(out_path, "_patched");
    }

    if (cmd == 'h') {
        print_usage(argv);
    } else if (cmd == 'p') {
        ret = patch_img(kimg_path, kpimg_path, out_path, superkey);
    } else if (cmd == 'd') {
        ret = dump_kallsym(kimg_path);
    } else if (cmd == 'u') {
        ret = unpatch_img(kimg_path, out_path);
    } else if (cmd == 'r') {
        ret = reset_key(kimg_path, out_path, superkey);
    } else if (cmd == 'v') {
        fprintf(stdout, "%x\n", version);
    } else {
        print_usage(argv);
    }
    return ret;
}
