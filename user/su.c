/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "su.h"

#include <stdio.h>
#include <getopt.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <error.h>

#include "supercall.h"

enum
{
    EXIT_TIMEDOUT = 124, /* Time expired before child completed.  */
    EXIT_CANCELED = 125, /* Internal error prior to exec attempt.  */
    EXIT_CANNOT_INVOKE = 126, /* Program located, but not usable.  */
    EXIT_ENOENT = 127 /* Could not find program to exec.  */
};

#ifdef ANDROID
#define DEFAULT_SHELL "/system/bin/sh"
#define DEFAULT_PATH "/product/bin:/apex/com.android.runtime/bin:/system/bin:/odm/bin:/vendor/bin:/usr/bin"
#define DEFAULT_ROOT_PATH \
    APATCH_BIN_FLODER     \
    ":" ADB_FLODER        \
    ":/sbin:/system/sbin:/product/bin:/apex/com.android.runtime/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin:/usr/bin:/user/sbin"

#else
#define DEFAULT_SHELL "/bin/sh"
#define DEFAULT_PATH ":/bin:/usr/bin"
#define DEFAULT_ROOT_PATH ":/usr/ucb:/bin:/usr/bin:/etc"
#endif

#define DEFAULT_USER "root"
#define PROGRAM_NAME "su"

static void run_shell(char const *, char const *, char **, size_t);
extern const char program_name[];
extern const char *key;

int setns(int __fd, int __ns_type);
int unshare(int __flags);

char *last_component(char const *name)
{
    char const *base = name;
    char const *p;
    bool last_was_slash = false;

    while (*base == '/')
        base++;

    for (p = base; *p; p++) {
        if (*p == '/')
            last_was_slash = true;
        else if (last_was_slash) {
            base = p;
            last_was_slash = false;
        }
    }

    return (char *)base;
}

/* Add NAME=VAL to the environment, checking for out of memory errors.  */
static void xsetenv(char const *name, char const *val)
{
    size_t namelen = strlen(name);
    size_t vallen = strlen(val);
    char *string = malloc(namelen + 1 + vallen + 1);
    strcpy(string, name);
    string[namelen] = '=';
    strcpy(string + namelen + 1, val);
    putenv(string);
}

static int switch_mnt_ns(int pid)
{
    int rc = 0;
    char mnt[32];
    snprintf(mnt, sizeof(mnt), "/proc/%d/ns/mnt", pid);
    if ((rc = access(mnt, R_OK)) < 0) {
        error(0, errno, "access %s error\n", mnt);
        return rc;
    }
    int fd = open(mnt, O_RDONLY);
    if (fd < 0) {
        error(0, errno, "access %s\n", mnt);
        rc = fd;
        return rc;
    }
    // switch to its namespace
    if ((rc = setns(fd, 0)) < 0) error(0, errno, "setns %d error\n", fd);
    close(fd);

    return rc;
}

static void set_identity(uid_t uid, gid_t *gids, int gids_num)
{
    gid_t gid;
    if (gids_num > 0) {
        if (setgroups(gids_num, gids)) error(EXIT_CANCELED, errno, "cannot set groups");
        gid = gids[0];
    } else {
        gid = uid;
    }
    if (setresgid(gid, gid, gid)) error(EXIT_CANCELED, errno, "cannot set gids");
    if (setresuid(uid, uid, uid)) error(EXIT_CANCELED, errno, "cannot set uids");
}

static void __attribute__((noreturn))
run_shell(char const *shell, char const *command, char **additional_args, size_t n_additional_args)
{
    size_t n_args = 1 + 2 * !!command + n_additional_args + 1;
    char const **args = malloc(n_args * sizeof *args);
    size_t argno = 1;

    args[0] = last_component(shell);
    if (command) {
        args[argno++] = "-c";
        args[argno++] = command;
    }
    memcpy(args + argno, additional_args, n_additional_args * sizeof *args);
    args[argno + n_additional_args] = NULL;
    execv(shell, (char **)args);

    {
        int exit_status = (errno == ENOENT ? -EXIT_ENOENT : EXIT_CANNOT_INVOKE);
        error(0, errno, "%s", shell);
        exit(exit_status);
    }
}

static void usage(int status)
{
    if (status != EXIT_SUCCESS)
        fprintf(stderr, "Try `%s help' for more information.\n", program_name);
    else {
        fprintf(stdout, "Change the user id, group id and security context.\n"
                        "If USER not given, assume root.\n\n");
        fprintf(stdout, "Usage: %s [OPTION]... [USER [ARG]...]\n\n", program_name);
        fprintf(
            stdout,
            "-h, --help                         Print this help message. \n"
            "-c, --command=COMMAND              pass a single COMMAND to the shell with -c\n"
            "-m, -p, --preserve-environment     do not reset environment variables\n"
            "-g, --group GROUP                  Specify the primary group\n"
            "-G, --supp-group GROUP             Specify a supplementary group.\n"
            "                                       The first specified supplementary group is also used\n"
            "                                       as a primary group if the option -g is not specified.\n"
            "-t, --target PID                   PID to take mount namespace from\n "
            "-i, --target-isolate               Use new isolated namespace if -t is specified.\n "
            "-s, --shell SHELL                  use SHELL instead of the default\n"
            "-, -l, --login                     Pretend the shell to be a login shell\n"
            "-Z, --context SCONTEXT             Switch security context to SCONTEXT, If SCONTEXT is not specified\n"
            "                                   or specified with a non-existent value, bypass all selinux permission\n"
            "                                   checks for all calls initiated by this task using hooks, \n"
            "                                   but the permission determined by other task remain unchanged. \n"
            "-M, --mount-master                 force run in the global mount namespace\n"
            "");
    }
    exit(status);
}

static struct option const longopts[] = { { "command", required_argument, 0, 'c' },
                                          { "help", no_argument, 0, 'h' },
                                          { "login", no_argument, 0, 'l' },
                                          { "preserve-environment", no_argument, 0, 'p' },
                                          { "shell", required_argument, 0, 's' },
                                          { "version", no_argument, 0, 'v' },
                                          { "context", required_argument, 0, 'Z' },
                                          { "mount-master", no_argument, 0, 'M' },
                                          { "target", required_argument, 0, 't' },
                                          { "target-isolate", required_argument, 0, 'i' },
                                          { "group", required_argument, 0, 'g' },
                                          { "supp-group", required_argument, 0, 'G' },
                                          { 0, 0, 0, 0 },
                                          { NULL, 0, NULL, 0 } };

uid_t uid = 0;
bool login = false;
bool keepenv = false;
bool isolated = false;
pid_t target = -1;

char *command = NULL;
char *shell = NULL;
char *scontext = NULL;

gid_t gids_num = 0;
gid_t gids[128] = { -1 };

const char *new_user = DEFAULT_USER;

int su_main(int argc, char **argv)
{
    int optc, c;

    struct passwd *pw;
    struct passwd pw_copy;

    pid_t origin_pid = getpid();

    while ((c = getopt_long(argc, argv, "c:hlmps:VvuZ:Mt:g:G:", longopts, 0)) != -1) {
        switch (c) {
        case 'c':
            command = optarg;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
        case 'l':
            login = true;
            break;
        case 'm':
        case 'p':
            keepenv = true;
            break;
        case 's':
            shell = optarg;
            break;
        case 'Z':
            scontext = optarg;
            break;
        case 'M':
        case 't':
            if (target != -1) {
                error(-EINVAL, 0, "Can't use -M and -t at the same time\n");
            }
            if (optarg == 0) {
                target = 0;
            } else {
                target = atol(optarg);
                if (*optarg == '-' || target == -1) {
                    error(-EINVAL, 0, "Invalid PID: %s\n", optarg);
                }
            }
            break;
        case 'i':
            isolated = true;
            break;
        case 'g':
        case 'G':
            if (atol(optarg) >= 0) {
                if (gids_num >= sizeof(gids) / sizeof(gids[0])) break;
                gids[gids_num++] = atol(optarg);
            } else {
                error(-EINVAL, 0, "Invalid GID: %s\n", optarg);
            }
            break;
        default:
            usage(EXIT_FAILURE);
        }
    }

    // login
    if (optind < argc && strcmp(argv[optind], "-") == 0) {
        login = true;
        optind++;
    }

    // user uid
    if (optind < argc) new_user = argv[optind++];

    pw = getpwnam(new_user);
    if (pw)
        uid = pw->pw_uid;
    else
        uid = atol(new_user);
    optind++;

    //  environment
    if (!shell && keepenv) shell = getenv("SHELL");
    if (!shell) shell = DEFAULT_SHELL;

    // su from kernel
    struct su_profile profile = { 0 };
    profile.uid = getuid();
    profile.to_uid = 0;
    if (scontext) strncpy(profile.scontext, scontext, sizeof(profile.scontext) - 1);
    if (sc_su(key, &profile)) error(-EACCES, 0, "incorrect super key");

    // session leader
    // setsid();

    // namespaces
    if (target > 0) { // namespace of pid
        if (switch_mnt_ns(target)) {
            error(0, errno, "switch_mnt_ns failed, fallback to global\n");
        } else {
            if (isolated) { // new isolated namespace
                if (unshare(CLONE_NEWNS) < 0) error(0, errno, "unshare");
                if (mount(0, "/", 0, MS_PRIVATE | MS_REC, 0) < 0) error(0, errno, "mount");
            }
        }
    }

    if (!keepenv) {
        xsetenv("HOME", pw->pw_dir);
        xsetenv("SHELL", shell);
        xsetenv("PATH", pw->pw_uid ? DEFAULT_PATH : DEFAULT_ROOT_PATH);
        if (pw->pw_uid) {
            xsetenv("USER", pw->pw_name);
            xsetenv("LOGNAME", pw->pw_name);
        }
    }

    set_identity(uid, gids, gids_num);

    if (chdir(pw->pw_dir) != 0) error(0, errno, "cannot change directory: %s", pw->pw_dir);

    if (ferror(stderr)) exit(EXIT_CANCELED);

    run_shell(shell, command, argv + optind, argc - optind > 0 ?: 0);
}