#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "kpatch.h"

#define SUPER_KEY_LEN 0x20

void print_usage(char **argv)
{
    char *c = "\n"
              " _  __                    _ ____       _       _     \n"
              "| |/ /___ _ __ _ __   ___| |  _ \\ __ _| |_ ___| |__  \n"
              "| ' // _ \\ '__| '_ \\ / _ \\ | |_) / _` | __/ __| '_ \\ \n"
              "| . \\  __/ |  | | | |  __/ |  __/ (_| | || (__| | | |\n"
              "|_|\\_\\___|_|  |_| |_|\\___|_|_|   \\__,_|\\__\\___|_| |_|\n"
              "\n"
              "KernelPatch Userspace Executable.\n"
              "Common Usage:\n"
              "./kpatch -h, --help\n"
              "    Print this message.\n"
              "./kpatch -v, --version\n"
              "    Print kpatch version.\n"
              "\n"
              "SuperCall Usage:\n"
              "./kpatch <super_key> <command> [args...]\n"
              "\n"
              "Command:\n"
              "  --hello\n"
              "     Print SuperCall hello message in the kernel. 'hello' will echoed\n"
              "     if KernelPatch installed successfully.\n"
              "  --kv\n"
              "     Get Kernel version.\n"
              "  --kpv\n"
              "     Get KernelPatch version.\n"
              "  --su [scontext]\n"
              "     Fork a root shell and change security context to 'scontext'.\n"
              "     If scontext is not specified or fails to be set, \n"
              "     bypass all selinux permission checks for all calls initiated by this thread using hooks,\n"
              "     but the permission determined by other threads remain unchanged.\n"
              "  --load_kpm path [args]\n"
              "     Load KernelPatch Module\n"
              "  --unload_kpm name\n"
              "     Unload KernelPatch Module\n"
              "  --kpm_num\n"
              "     Get the number of KernelPatch Modules\n"
              "  --kpm_info index\n"
              "     Get information of the module at 'index'.\n"
              "  --thread_su tid\n"
              "     Grant root privileges to the thread corresponding to the given 'tid'.\n"
              "  --thread_unsu tid\n"
              "     Revoke root privileges to the thread corresponding to the given 'tid'.\n"
              "     (Unimplemented ...).\n"
#ifdef ANDROID
              "\n"
              "Android Specific Command:\n"
              "     The default command to get a root shell is 'kp', whose full path is '/system/bin/kp'.\n"
              "     This can avoid conflicts with the existing 'su' command.\n"
              "     If you want to change this path, you can use the 'reset_su' command.\n"
              "  --grant_su uid\n"
              "     Grant root privileges to the user corresponding to the given 'uid'.\n"
              "  --revoke_su uid\n"
              "     Revoke root privileges to the user corresponding to the given 'uid'.\n"
              "  --num_su\n"
              "     Get the number of su allowed uids\n"
              "  --list_su\n"
              "     List su allowed uids.\n"
              "  --reset_su path\n"
              "     Reset root shell command full path to 'path'. The length of 'path' must not exceed 14 characters.\n"
              "  --get_su\n"
              "     Get full path of current root shell command.\n"
#endif
              "\n";
    fprintf(stdout, "%s", c);
}

int main(int argc, char **argv)
{
    int cmd = -1;
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

    if (!strnlen(argv[1], SUPER_KEY_LEN)) {
        fprintf(stderr, "Super key must be specified\n");
        return -1;
    }
    const char *key = argv[1];

    struct option longopts[] = { { "hello", no_argument, &cmd, SUPERCALL_HELLO },
                                 { "kv", no_argument, &cmd, SUPERCALL_GET_KERNEL_VERSION },
                                 { "kpv", no_argument, &cmd, SUPERCALL_GET_KP_VERSION },
                                 { "load_kpm", no_argument, &cmd, SUPERCALL_LOAD_KPM },
                                 { "unload_kpm", no_argument, &cmd, SUPERCALL_UNLOAD_KPM },
                                 { "kpm_num", no_argument, &cmd, SUPERCALL_KPM_NUMS },
                                 { "kpm_info", no_argument, &cmd, SUPERCALL_KPM_INFO },
                                 { "su", no_argument, &cmd, SUPERCALL_SU },
                                 { "thread_su", no_argument, &cmd, SUPERCALL_THREAD_SU },
                                 { "thread_unsu", no_argument, &cmd, SUPERCALL_THREAD_UNSU },
#ifdef ANDROID
                                 { "grant_su", no_argument, &cmd, SUPERCALL_GRANT_SU },
                                 { "revoke_su", no_argument, &cmd, SUPERCALL_REVOKE_SU },
                                 { "num_su", no_argument, &cmd, SUPERCALL_SU_ALLOW_NUM },
                                 { "list_su", no_argument, &cmd, SUPERCALL_LIST_SU_ALLOW },
                                 { "reset_su", no_argument, &cmd, SUPERCALL_SU_RESET_PATH },
                                 { "get_su", no_argument, &cmd, SUPERCALL_SU_GET_PATH },
#endif
                                 { 0, 0, 0, 0 } };
    char *optstr = "";
    int opt = -1;
    int opt_index = -1;
    int verbose = 0;
    while ((opt = getopt_long(argc, argv, optstr, longopts, &opt_index)) != -1) {
        switch (opt) {
        }
    }

    long ret = 0;
    if (cmd == SUPERCALL_HELLO) {
        ret = sc_hello(key);
        if (ret == SUPERCALL_HELLO_MAGIC) {
            fprintf(stdout, "hello\n");
            ret = 0;
        }
    } else if (cmd == SUPERCALL_GET_KERNEL_VERSION) {
        long kv = sc_get_kernel_version(key);
        fprintf(stdout, "%lx\n", kv);
    } else if (cmd == SUPERCALL_GET_KP_VERSION) {
        long kpv = sc_get_kp_version(key);
        fprintf(stdout, "%lx\n", kpv);
    } else if (cmd == SUPERCALL_LOAD_KPM) {
        if (argc < 4) {
            fprintf(stderr, "Empty path!\n");
            return -1;
        }
        const char *path = argv[3];
        const char *args = argc < 5 ? NULL : argv[4];
        ret = sc_load_kpm(key, path, args);
    } else if (cmd == SUPERCALL_UNLOAD_KPM) {
        if (argc < 4) {
            fprintf(stderr, "Empty name!\n");
            return -1;
        }
        const char *name = argv[3];
        ret = sc_unload_kpm(key, name);
    } else if (cmd == SUPERCALL_KPM_NUMS) {
        int num = sc_kpm_nums(key);
        fprintf(stdout, "%d\n", num);
        ret = 0;
    } else if (cmd == SUPERCALL_KPM_INFO) {
        if (argc < 4) {
            fprintf(stderr, "Empty index!\n");
            return -1;
        }
        const char *si = argv[3];
        int index = atoi(si);
        char buf[1024];
        long ret = sc_kpm_info(key, index, buf, sizeof(buf));
        if (ret > 0) {
            fprintf(stdout, "index: %d\n", index);
            fprintf(stdout, "%s", buf);
            ret = 0;
        }
    } else if (cmd == SUPERCALL_SU) {
        const char *scontext = argc < 4 ? NULL : argv[3];
        ret = su_fork(key, scontext);
    } else if (cmd == SUPERCALL_THREAD_SU) {
        if (argc < 4) {
            fprintf(stderr, "Empty tid!\n");
            return -1;
        }
        const char *stid = argv[3];
        int pid = atoi(stid);
        ret = sc_thread_su(key, pid, 0);
    } else if (cmd == SUPERCALL_THREAD_UNSU) {
        if (argc < 4) {
            fprintf(stderr, "Empty tid!\n");
            return -1;
        }
        const char *stid = argv[3];
        int pid = atoi(stid);
        ret = sc_thread_unsu(key, pid);
    }
#ifdef ANDROID
    else if (cmd == SUPERCALL_GRANT_SU) {
        if (argc < 4) {
            fprintf(stderr, "Empty uid!\n");
            return -1;
        }
        const char *suid = argv[3];
        uid_t uid = atoi(suid);
        ret = sc_grant_su(key, uid);
    } else if (cmd == SUPERCALL_REVOKE_SU) {
        if (argc < 4) {
            fprintf(stderr, "Empty uid!\n");
            return -1;
        }
        const char *suid = argv[3];
        uid_t uid = atoi(suid);
        ret = sc_revoke_su(key, uid);
    } else if (cmd == SUPERCALL_SU_ALLOW_NUM) {
        int num = sc_num_su(key);
        fprintf(stdout, "%d\n", num);
        ret = 0;
    } else if (cmd == SUPERCALL_LIST_SU_ALLOW) {
        uid_t uids[SUPERCALL_SU_ALLOW_UID_MAX];
        ret = sc_list_su_allow(key, uids, SUPERCALL_SU_ALLOW_UID_MAX);
        for (int i = 0; i < ret; i++) {
            fprintf(stdout, "%d\t", uids[i]);
        }
        fprintf(stdout, "\n");
        ret = 0;
    } else if (cmd == SUPERCALL_SU_RESET_PATH) {
        if (argc < 4) {
            fprintf(stderr, "Empty path!\n");
            return -1;
        }
        const char *path = argv[3];
        if (strnlen(path, SUPERCALL_SU_PATH_LEN) >= SUPERCALL_SU_PATH_LEN) {
            fprintf(stderr, "The length of the 'path' should not exceed the length of /system/bin/sh.\n");
            return -1;
        }
        ret = sc_su_reset_path(key, path);
    } else if (cmd == SUPERCALL_SU_GET_PATH) {
        char path[32] = { '\0' };
        ret = sc_su_get_path(key, path, 32);
        fprintf(stdout, "%s\n", path);
        if (ret > 0) ret = 0;
    }
#endif
    else {
        fprintf(stderr, "Invalid SuperCall command!\n");
        return 0;
    }

    return ret;
}
