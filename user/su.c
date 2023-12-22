
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
/* If true, change some environment vars to indicate the user su'd to.  */
static bool change_environment;

extern const char program_name[];

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

/* Become the user and group(s) specified by PW.  */
static void change_identity(const struct passwd *pw)
{
    errno = 0;
    if (initgroups(pw->pw_name, pw->pw_gid) == -1) error(EXIT_CANCELED, errno, "cannot set groups");
    endgrent();
    if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid)) error(EXIT_CANCELED, errno, "cannot set group id");
    if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid)) error(EXIT_CANCELED, errno, "cannot set user id");
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
        fprintf(stdout,
                "-h, --help                       Print this help message. \n"
                "-c, --command=COMMAND        pass a single COMMAND to the shell with -c\n"
                "-m, --preserve-environment   do not reset environment variables\n"
                "-p                           same as -m\n"
                "-s, --shell=SHELL            use SHELL instead of the default\n"
                "-x, --scontext=SCONTEXT      Switch security context to SCONTEXT, If SCONTEXT is not specified\n"
                "                             or specified with a non-existent value, bypass all selinux permission\n"
                "                             checks for all calls initiated by this task using hooks, \n"
                "                             but the permission determined by other task remain unchanged. \n"
                "");
    }
    exit(status);
}

static struct option const longopts[] = {
    { "command", required_argument, NULL, 'c' }, { "preserve-environment", no_argument, NULL, 'p' },
    { "shell", required_argument, NULL, 's' },   { "scontext", required_argument, NULL, 'x' },
    { "--help", no_argument, NULL, 'h' },        { NULL, 0, NULL, 0 }
};

int su_main(const char *key, int argc, char **argv)
{
    int optc;
    const char *new_user = DEFAULT_USER;
    char *command = NULL;
    char *shell = NULL;
    char *scontext = NULL;
    struct passwd *pw;

    change_environment = true;

    while ((optc = getopt_long(argc, argv, "c:flmps:x:h", longopts, NULL)) != -1) {
        switch (optc) {
        case 'c':
            command = optarg;
            break;
        case 'm':
        case 'p':
            change_environment = false;
            break;
        case 's':
            shell = optarg;
            break;
        case 'x':
            scontext = optarg;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
        default:
            usage(EXIT_FAILURE);
        }
    }

    if (optind < argc) new_user = argv[optind++];

    //
    struct su_profile profile = { 0 };
    profile.uid = getuid();
    if (scontext) {
        strncpy(profile.scontext, scontext, sizeof(profile.scontext) - 1);
    }

    if (sc_su(key, &profile)) error(-EACCES, 0, "incorrect super key");

    pw = getpwnam(new_user);
    if (!(pw && pw->pw_name && pw->pw_name[0] && pw->pw_dir && pw->pw_dir[0]))
        error(EXIT_CANCELED, 0, "user %s does not exist", new_user);
    pw->pw_shell = strdup(pw->pw_shell && pw->pw_shell[0] ? pw->pw_shell : DEFAULT_SHELL);
    endpwent();

    if (!shell && !change_environment) shell = getenv("SHELL");
    shell = strdup(shell ? shell : pw->pw_shell);

    if (change_environment) {
        xsetenv("HOME", pw->pw_dir);
        xsetenv("SHELL", shell);
        // add path
        // char *old_path = getenv("PATH");
        // char *add_path = pw->pw_uid ? DEFAULT_PATH : DEFAULT_ROOT_PATH;
        // int path_len = strlen(old_path) + strlen(add_path) + 1;
        // char *new_path = malloc(path_len);
        // memset(new_path, 0, path_len);
        // strcat(new_path, old_path);
        // strcat(new_path, add_path);
        // xsetenv("PATH", new_path);
        // free(new_path);
        xsetenv("PATH", pw->pw_uid ? DEFAULT_PATH : DEFAULT_ROOT_PATH);
        if (pw->pw_uid) {
            xsetenv("USER", pw->pw_name);
            xsetenv("LOGNAME", pw->pw_name);
        }
    }

    change_identity(pw);

    if (chdir(pw->pw_dir) != 0) error(0, errno, "warning: cannot change directory to %s", pw->pw_dir);

    if (ferror(stderr)) exit(EXIT_CANCELED);

    run_shell(shell, command, argv + optind, argc - optind > 0 ?: 0);
}