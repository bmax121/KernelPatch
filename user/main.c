#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libkp.h"

#define SUPER_KEY_LEN 0x20
char key[SUPER_KEY_LEN] = { '\0' };

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
              "./kpatch <-k your_key> <command> [args...]\n"
              "command:\n"
              "  --hello\n"
              "     Print SuperCall hello message in the kernel. Return 0 if succeed, others if failed!\n"
              "  --kv\n"
              "     Get Kernel version.\n"
              "  --kpv\n"
              "     Get KernelPatch version.\n"
              "  --su\n"
              "     Fork a default root shell.\n"
              "  --grant_su --arg2 tid\n"
              "     Grant root privileges to the thread corresponding to the given tid.\n"
              "  --revoke_su --arg2 tid\n"
              "     Revoke root privileges to the thread corresponding to the given tid.\n"
              "  --load_kpm --arg2 kpm_patch\n"
              "     (Unimplemented ...).\n"
              "  --unload_kpm --arg2 kpm_patch\n"
              "     (Unimplemented ...).\n"
              "\n";
    fprintf(stdout, "%s", c);
}

int main(int argc, char **argv)
{
    int cmd = -1;
    char *arg2 = 0, *arg3 = 0, *arg4 = 0, *arg5 = 0;
    if (argc == 1) {
        print_usage(argv);
        return 0;
    }

    struct option longopts[] = { { "help", no_argument, NULL, 'h' },
                                 { "version", no_argument, NULL, 'v' },
                                 { "key", required_argument, NULL, 'k' },
                                 { "arg2", required_argument, NULL, '2' },
                                 { "arg3", required_argument, NULL, '3' },
                                 { "arg4", required_argument, NULL, '4' },
                                 { "arg5", required_argument, NULL, '5' },
                                 { "hello", no_argument, &cmd, SUPERCALL_HELLO },
                                 { "kv", no_argument, &cmd, SUPERCALL_GET_KERNEL_VERSION },
                                 { "kpv", no_argument, &cmd, SUPERCALL_GET_KP_VERSION },
                                 { "su", no_argument, &cmd, SUPERCALL_SU },
                                 { "grant_su", no_argument, &cmd, SUPERCALL_GRANT_SU },
                                 { "revoke_su", no_argument, &cmd, SUPERCALL_REVOKE_SU },
                                 { 0, 0, 0, 0 } };
    char *optstr = "hvk:2:3:4:5:";
    int opt = -1;
    int opt_index = -1;
    int verbose = 0;
    while ((opt = getopt_long(argc, argv, optstr, longopts, &opt_index)) != -1) {
        switch (opt) {
        case 'h':
            print_usage(argv);
            return 0;
        case 'v':
            fprintf(stdout, "%x\n", get_version());
            return 0;
        case 'k':
            strncpy(key, optarg, SUPER_KEY_LEN);
            break;
        case '2':
            arg2 = optarg;
            break;
        case '3':
            arg3 = optarg;
            break;
        case '4':
            arg4 = optarg;
            break;
        case '5':
            arg5 = optarg;
            break;
        default:
            break;
        }
    }
    if (!strnlen(key, SUPER_KEY_LEN)) {
        fprintf(stderr, "Super key must be specified\n");
        return -1;
    }

    // fprintf(stdout, "key: %s, command no: %x, arg2: %s, arg3:%s, arg4: %s, arg5: %s\n", key, cmd, arg2, arg3, arg4,
    //         arg5);

    long ret = 0;
    if (cmd == SUPERCALL_HELLO) {
        ret = sc_hello(key);
    } else if (cmd == SUPERCALL_GET_KERNEL_VERSION) {
        long kv = sc_get_kernel_version(key);
        fprintf(stdout, "%lx\n", kv);
    } else if (cmd == SUPERCALL_GET_KP_VERSION) {
        long kpv = sc_get_kp_version(key);
        fprintf(stdout, "%lx\n", kpv);
    } else if (cmd == SUPERCALL_SU) {
        ret = su_fork(key);
    } else if (cmd == SUPERCALL_GRANT_SU) {
        if (!arg2) {
            fprintf(stderr, "Empty Tid!\n");
            return -1;
        }
        int pid = atoi(arg2);
        ret = sc_grant_su(key, pid);
    } else if (cmd == SUPERCALL_REVOKE_SU) {
        if (!arg2) {
            fprintf(stderr, "Empty Tid!\n");
            return -1;
        }
        int pid = atoi(arg2);
        ret = sc_revoke_su(key, pid);
    } else {
        fprintf(stderr, "Invalid SuperCall command!\n");
        return 0;
    }
    // fprintf(stdout, "ret: %ld\n", ret);
    return ret;
}
