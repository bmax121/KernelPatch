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
#include "android/user_init.h"
#endif

char program_name[128] = { '\0' };

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
                "%s -h, --help       Print this message. \n"
                "%s -v, --version    Print version. \n"
                "\n",
                program_name, program_name);
        fprintf(stdout, "Usage: %s <SUPERKEY> <COMMAND> [-h, --help] [COMMAND_ARGS]...\n", program_name);
        fprintf(stdout,
                "\n"
                "Commands:\n"
                "hello       If KernelPatch installed, '%s' will echoed.\n"
                "version     Print KernelPatch version.\n"
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

int main(int argc, char **argv)
{
    strcat(program_name, argv[0]);

    if (argc == 1) usage(EXIT_FAILURE);

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

    const char *key = argv[1];
    if (!key[0]) error(-EINVAL, 0, "superkey does not exist");

    if (strnlen(key, SUPERCALL_KEY_MAX_LEN) >= SUPERCALL_KEY_MAX_LEN) error(-EINVAL, 0, "superkey too long");

    const char *scmd = argv[2];
    int cmd = -1;

    struct
    {
        const char *scmd;
        int cmd;
    } cmd_arr[] = {
        { "hello", SUPERCALL_HELLO },
        { "version", SUPERCALL_KP_VERSION },
        { "su", 's' },
        { "kpm", 'k' },
        { "--help", 'h' },
        { "-h", 'h' },
#ifdef ANDROID
        { "sumgr", 'm' },
        { "android_user_init", 'a' },
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
        return hello(key);
    case SUPERCALL_KP_VERSION:
        return kpv(key);
    case 's':
        strcat(program_name, " <SUPERKEY> su");
        return su_main(key, argc - 2, argv + 2);
    case 'k':
        strcat(program_name, " <SUPERKEY> kpm");
        return kpm_main(key, argc - 2, argv + 2);
    case 'm':
        strcat(program_name, " <SUPERKEY> sumgr");
        return sumgr_main(key, argc - 2, argv + 2);
    case 'a':
        return android_user_init(key);
    case 'h':
        usage(EXIT_SUCCESS);
    default:
        fprintf(stderr, "Invalid command: %s!\n", scmd);
        return -EINVAL;
    }

    return 0;
}
