#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libkp.h"

#define SUPER_KEY_LEN 0x20

void print_usage(char **argv)
{
    char *c = "\nkpatch: KernelPatch Userspace Executable.\n"
              "\n"
              "Common Usage:\n"
              "./kpatch -h, --help\n"
              "    Print this message.\n"
              "./kpatch -v, --version\n"
              "    Print kpatch version.\n"
              "\n"
              "SuperCall Usage:\n"
              "./kpatch <super_key> <command> [args...]\n"
              "command:\n"
              "  --hello\n"
              "     Print SuperCall hello message in the kernel. Return 0 if succeed, others if failed!\n"
              "  --kv\n"
              "     Get Kernel version.\n"
              "  --kpv\n"
              "     Get KernelPatch version.\n"
              "  --su\n"
              "     Fork a default root shell.\n"
              "  --load_kpm --arg1 kpm_patch\n"
              "     Load KernelPatch Module\n"
              "     (Unimplemented ...).\n"
              "  --unload_kpm --arg1 kpm_patch\n"
              "     Unload KernelPatch Module\n"
              "     (Unimplemented ...).\n"
              "  --grant_su --arg1 uid\n"
              "     Grant root privileges to the user corresponding to the given uid.\n"
              "     (Unimplemented ...).\n"
              "  --revoke_su --arg1 uid\n"
              "     Revoke root privileges to the user corresponding to the given uid.\n"
              "     (Unimplemented ...).\n"
              "  --thread_su --arg1 tid\n"
              "     Grant root privileges to the thread corresponding to the given tid.\n"
              "  --thread_unsu --arg1 tid\n"
              "     Revoke root privileges to the thread corresponding to the given tid.\n"
              "     (Unimplemented ...).\n"
              "\n";
    fprintf(stdout, "%s", c);
}

int main(int argc, char **argv)
{
    int cmd = -1;
    char *arg1 = 0, *arg2 = 0, *arg3 = 0;

    if (argc == 2) {
        if (!strcmp(argv[1], "-v") || !(strcmp(argv[1], "--version"))) {
            fprintf(stdout, "%x\n", get_version());
            return 0;
        }
    }

    if (argc < 3) {
        print_usage(argv);
        return 0;
    }

    char key[SUPER_KEY_LEN] = { '\0' };
    strncpy(key, argv[1], SUPER_KEY_LEN);

    if (!strnlen(key, SUPER_KEY_LEN)) {
        fprintf(stderr, "Super key must be specified\n");
        return -1;
    }

    struct option longopts[] = { { "arg1", required_argument, NULL, '1' },
                                 { "arg2", required_argument, NULL, '2' },
                                 { "arg3", required_argument, NULL, '3' },
                                 { "hello", no_argument, &cmd, SUPERCALL_HELLO },
                                 { "kv", no_argument, &cmd, SUPERCALL_GET_KERNEL_VERSION },
                                 { "kpv", no_argument, &cmd, SUPERCALL_GET_KP_VERSION },
                                 { "load_kpm", no_argument, NULL, SUPERCALL_LOAD_KPM },
                                 { "unload_kpm", no_argument, NULL, SUPERCALL_UNLOAD_KPM },
                                 { "su", no_argument, &cmd, SUPERCALL_SU },
                                 { "grant_su", no_argument, &cmd, SUPERCALL_GRANT_SU },
                                 { "revoke_su", no_argument, &cmd, SUPERCALL_REVOKE_SU },
                                 { "thread_su", no_argument, &cmd, SUPERCALL_THREAD_SU },
                                 { "thread_unsu", no_argument, &cmd, SUPERCALL_THREAD_UNSU },

                                 { 0, 0, 0, 0 } };
    char *optstr = "1:2:3:";
    int opt = -1;
    int opt_index = -1;
    int verbose = 0;
    while ((opt = getopt_long(argc, argv, optstr, longopts, &opt_index)) != -1) {
        switch (opt) {
        case '1':
            arg1 = optarg;
            break;
        case '2':
            arg2 = optarg;
            break;
        case '3':
            arg3 = optarg;
            break;
        default:
            continue;
        }
    }

    // fprintf(stdout, "command no: %x, arg1: %s, arg2: %s, arg3:%s\n", cmd, arg1, arg2, arg3);

    long ret = 0;
    if (cmd == SUPERCALL_HELLO) {
        ret = sc_hello(key);
        if (ret == SUPERCALL_HELLO_MAGIC)
            ret = 0;
    } else if (cmd == SUPERCALL_GET_KERNEL_VERSION) {
        long kv = sc_get_kernel_version(key);
        fprintf(stdout, "%lx\n", kv);
    } else if (cmd == SUPERCALL_GET_KP_VERSION) {
        long kpv = sc_get_kp_version(key);
        fprintf(stdout, "%lx\n", kpv);
    } else if (cmd == SUPERCALL_SU) {
        ret = su_fork(key);
    } else if (cmd == SUPERCALL_THREAD_SU) {
        if (!arg1) {
            fprintf(stderr, "Empty Tid!\n");
            return -1;
        }
        int pid = atoi(arg1);
        ret = sc_grant_su(key, pid);
    } else if (cmd == SUPERCALL_REVOKE_SU) {
        if (!arg1) {
            fprintf(stderr, "Empty Tid!\n");
            return -1;
        }
        int pid = atoi(arg1);
        ret = sc_revoke_su(key, pid);
    } else {
        fprintf(stderr, "Invalid SuperCall command!\n");
        return 0;
    }
    if (ret == SUPERCALL_RES_NOT_IMPL) {
        fprintf(stdout, "Unimplemented SuperCall\n");
    }
    return ret;
}
