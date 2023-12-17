#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "../banner"
#include "kpatch.h"
#include "uapi/scdefs.h"

#ifdef ANDROID
#define ANDROID_USER_INIT_CMD 0x100
#endif

static void print_usage(char **argv)
{
    const char *help = "KernelPatch userspace cli. \n"
                       "" KERNEL_PATCH_BANNER " \n"
                       "Usage: \n"
                       "%s -h, --help \n"
                       "    Print this message. \n"
                       "%s -v, --version \n"
                       "    Print version. \n"
                       "\n";
    fprintf(stdout, help, argv[0], argv[0]);

    const char *help_sc =
        "SuperCall Usage: \n"
        "%s <super_key> <command> [args...] \n"
        "\n"
        "Commnads: \n"
        "    --hello \n"
        "         '%s' will echoed if KernelPatch installed successfully. \n"
        "    --kpv \n"
        "         Get KernelPatch version. \n"
        "    --su [to_uid] [scontext] \n"
        "         Start a new shell with specified 'to_uid' and 'scontext', \n"
        "         If 'scontext' is not specified or specified with a non-existent value, \n"
        "         bypass all selinux permission checks for all calls initiated by this task using hooks, \n"
        "         but the permission determined by other task remain unchanged. \n"
        "    --su_thread tid [to_uid] [scontext] \n"
        "         Set the UID and security context of the thread corresponding to the 'tid'(gettid(2)) \n"
        "         to the specified 'to_uid' and 'scontext'. \n"
        "         However, these settings will not be propagated to the child tasks. (todo) \n"
        "    --kpm_load path \n"
        "         Load KernelPatch Module with path 'path'. \n"
        "    --kpm_unload name \n"
        "         Unload KernelPatch Module named 'name'. \n"
        "    --kpm_num \n"
        "         Get the number of modules that have been loaded. \n"
        "    --kpm_list \n"
        "         List the module names of all loaded modules. \n"
        "    --kpm_info name \n"
        "         Get detailed information about a module by its module 'name' \n"
        "\n";
    fprintf(stdout, help_sc, argv[0], SUPERCALL_HELLO_ECHO);
#ifdef ANDROID
    const char *help_android =
        "Commands(Android specified):\n"
        "    The default command obtain a shell with the specified 'to_uid' and 'scontext' is 'kp', \n"
        "    whose full path is '/system/bin/kp'. This can avoid conflicts with the existing 'su' command. \n"
        "    If you wish to modify this path, you can use the '--su_reset' command. \n"
        "\n"
        "    --su_grant uid [to_uid] [scontext] \n"
        "         Grant permission for 'uid' to execute the '/system/bin/kp', \n"
        "    --su_revoke uid \n"
        "         Revoke permission. \n"
        "    --su_num \n"
        "         Get the number of uids with the aforementioned permissions. \n"
        "    --su_list \n"
        "         List aforementioned uids. \n"
        "    --su_profile uid \n"
        "         Get the profile of the uid configuration. \n"
        "    --su_reset path \n"
        "         Reset '/system/bin/kp' to 'path'. The length of 'path' must be between 15-64, \n"
        "         including the terminating null byte ('\\0'). \n"
        "    --su_get \n"
        "         Get current path. \n"
        "\n";
    fprintf(stdout, "%s", help_android);
#endif
}

int main(int argc, char **argv)
{
    if (argc == 1) {
        fprintf(stdout, "Try '%s -h' to get help.\n", argv[0]);
        return 0;
    }

    if (argc == 2) {
        if (!strcmp(argv[1], "-v") || !(strcmp(argv[1], "--version"))) {
            fprintf(stdout, "%x\n", version());
        } else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            print_usage(argv);
        } else {
            fprintf(stdout, "Try '%s -h' to get help.\n", argv[0]);
        }
        return 0;
    }

    const char *key = argv[1];
    if (!key[0]) {
        fprintf(stderr, "Empty SuperKey!\n");
        return -EINVAL;
    }

    if (strnlen(key, SUPERCALL_KEY_MAX_LEN) >= SUPERCALL_KEY_MAX_LEN) {
        fprintf(stderr, "SuperKey too long!\n");
        return -E2BIG;
    }

    const char *scmd = argv[2];

    int cmd = -1;

    struct option longopts[] = { { "help", no_argument, &cmd, 'h' },
                                 { "version", no_argument, &cmd, 'v' },

                                 { "hello", no_argument, &cmd, SUPERCALL_HELLO },
                                 { "kpv", no_argument, &cmd, SUPERCALL_KP_VERSION },
                                 { "su", no_argument, &cmd, SUPERCALL_SU },
                                 { "su_thread", no_argument, &cmd, SUPERCALL_SU_TASK },
                                 { "kpm_load", no_argument, &cmd, SUPERCALL_KPM_LOAD },
                                 { "kpm_unload", no_argument, &cmd, SUPERCALL_KPM_UNLOAD },
                                 { "kpm_num", no_argument, &cmd, SUPERCALL_KPM_NUMS },
                                 { "kpm_list", no_argument, &cmd, SUPERCALL_KPM_LIST },
                                 { "kpm_info", no_argument, &cmd, SUPERCALL_KPM_INFO },
                                 { "test", no_argument, &cmd, SUPERCALL_TEST },
#ifdef ANDROID
                                 { "su_grant", no_argument, &cmd, SUPERCALL_SU_GRANT_UID },
                                 { "su_revoke", no_argument, &cmd, SUPERCALL_SU_REVOKE_UID },
                                 { "su_num", no_argument, &cmd, SUPERCALL_SU_NUMS },
                                 { "su_list", no_argument, &cmd, SUPERCALL_SU_LIST },
                                 { "su_profile", no_argument, &cmd, SUPERCALL_SU_PROFILE },
                                 { "su_reset", no_argument, &cmd, SUPERCALL_SU_RESET_PATH },
                                 { "su_get", no_argument, &cmd, SUPERCALL_SU_GET_PATH },
                                 { "android_user_init", no_argument, &cmd, ANDROID_USER_INIT_CMD },
#endif
                                 { 0, 0, 0, 0 } };
    char *optstr = "hv";
    int opt = -1;
    int opt_index = -1;
    int verbose = 0;
    while ((opt = getopt_long(argc, argv, optstr, longopts, &opt_index)) != -1) {
        switch (opt) {
        case 'h':
            print_usage(argv);
            return 0;
        case 'v':
            fprintf(stdout, "%x\n", version());
            return 0;
        default:
            break;
        }
    }

    if (cmd == -1) {
        fprintf(stdout, "Try '%s ****** -h' to get help.\n", argv[0]);
        return 0;
    }

    uid_t uid = 0;
    uid_t to_uid = 0;
    const char *sctx = NULL;
    const char *path = NULL;
    const char *mod_args = NULL;
    const char *name = NULL;

    switch (cmd) {
    case SUPERCALL_HELLO:
        return hello(key);
    case SUPERCALL_KP_VERSION:
        return kpv(key);
    case SUPERCALL_SU:
        if (argc >= 4) to_uid = (uid_t)atoi(argv[3]);
        if (argc >= 5) sctx = argv[4];
        return su_fork(key, to_uid, sctx);
    case SUPERCALL_SU_TASK:
        if (argc >= 4) uid = (uid_t)atoi(argv[3]);
        if (argc >= 5) to_uid = (uid_t)atoi(argv[4]);
        if (argc >= 6) sctx = argv[5];
        return su_thread(key, uid, to_uid, sctx);
    case SUPERCALL_KPM_LOAD:
        if (argc < 4) {
            fprintf(stderr, "Empyt module path!\n");
            return -EINVAL;
        }
        path = argv[3];
        mod_args = argc >= 5 ? NULL : argv[4];
        return kpm_load(key, path, mod_args);
    case SUPERCALL_KPM_UNLOAD:
        if (argc < 4) {
            fprintf(stderr, "Empyt module name!\n");
            return -EINVAL;
        }
        name = argv[3];
        return kpm_unload(key, name);
    case SUPERCALL_KPM_NUMS:
        return kpm_nums(key);
    case SUPERCALL_KPM_LIST:
        return kpm_list(key);
    case SUPERCALL_KPM_INFO:
        if (argc < 4) {
            fprintf(stderr, "Empyt module name!\n");
            return -EINVAL;
        }
        name = argv[3];
        return kpm_info(key, name);
    case SUPERCALL_TEST:
        return __test(key);
#ifdef ANDROID
    case SUPERCALL_SU_GRANT_UID:
        if (argc < 4) {
            fprintf(stderr, "Empyt uid!\n");
            return -EINVAL;
        }
        uid = (uid_t)atoi(argv[3]);
        if (argc >= 5) to_uid = (uid_t)atoi(argv[4]);
        if (argc >= 6) sctx = argv[5];
        return su_grant(key, uid, to_uid, sctx);
    case SUPERCALL_SU_REVOKE_UID:
        if (argc < 4) {
            fprintf(stderr, "Empyt uid!\n");
            return -EINVAL;
        }
        uid = (uid_t)atoi(argv[3]);
        return su_revoke(key, uid);
    case SUPERCALL_SU_NUMS:
        return su_nums(key);
    case SUPERCALL_SU_LIST:
        return su_list(key);
    case SUPERCALL_SU_PROFILE:
        if (argc < 4) {
            fprintf(stderr, "Empyt uid!\n");
            return -EINVAL;
        }
        uid = (uid_t)atoi(argv[3]);
        return su_profile(key, uid);
    case SUPERCALL_SU_RESET_PATH:
        if (argc < 4) {
            fprintf(stderr, "Empyt module path!\n");
            return -EINVAL;
        }
        path = argv[3];
        return su_reset_path(key, path);
    case SUPERCALL_SU_GET_PATH:
        return su_get_path(key);
    case ANDROID_USER_INIT_CMD:
        return android_user_init(key);
#endif
    default:
        fprintf(stderr, "Invalid command: %s!\n", scmd);
        return -EINVAL;
    }
    return 0;
}
