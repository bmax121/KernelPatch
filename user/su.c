
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
#define DEFAULT_LOGIN_PATH ":/usr/bin:/user/sbin"
#define DEFAULT_ROOT_LOGIN_PATH ":/data/adb:/data/adb/ap/bin"
#else
#define DEFAULT_SHELL "/bin/sh"
#define DEFAULT_LOGIN_PATH ":/bin:/usr/bin"
#define DEFAULT_ROOT_LOGIN_PATH ":/usr/ucb:/bin:/usr/bin:/etc"
#endif

#define DEFAULT_USER "root"
#define PROGRAM_NAME "su"

char *crypt(char const *key, char const *salt);
static void run_shell(char const *, char const *, char **, size_t);
/* If true, change some environment vars to indicate the user su'd to.  */
static bool change_environment;

static const char *program_name;

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
    if (setgid(pw->pw_gid)) error(EXIT_CANCELED, errno, "cannot set group id");
    if (setuid(pw->pw_uid)) error(EXIT_CANCELED, errno, "cannot set user id");
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

void usage(int status)
{
    if (status != EXIT_SUCCESS)
        fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
    else {
        printf("Usage: %s [OPTION]... [USER [ARG]...]\n\n", program_name);
        fprintf(stdout, ""
                        "Change the effective user id and group id to that of USER.\n"
                        "If USER not given, assume root.\n\n"
                        "-c, --command=COMMAND        pass a single COMMAND to the shell with -c\n"
                        "-m, --preserve-environment   do not reset environment variables\n"
                        "-p                           same as -m\n"
                        "-s, --shell=SHELL            run SHELL if /etc/shells allows it\n"
                        "");
    }
    exit(status);
}

static struct option const longopts[] = {
    { "command", required_argument, NULL, 'c' }, { "preserve-environment", no_argument, NULL, 'p' },
    { "shell", required_argument, NULL, 's' },   { "context", required_argument, NULL, 'x' },
    { "help", no_argument, NULL, 'h' },          { NULL, 0, NULL, 0 }
};

int su_main(const char *key, int argc, char **argv)
{
    int optc;
    const char *new_user = DEFAULT_USER;
    char *command = NULL;
    char *shell = NULL;
    char *scontext = NULL;
    struct passwd *pw;

    program_name = argv[0];

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
    sc_su(key, &profile);

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
        char *old_path = getenv("PATH");
        char *add_path = pw->pw_uid ? DEFAULT_LOGIN_PATH : DEFAULT_ROOT_LOGIN_PATH;
        int path_len = strlen(old_path) + strlen(add_path) + 1;
        char *new_path = malloc(path_len);
        memset(new_path, 0, path_len);
        strcat(new_path, old_path);
        strcat(new_path, add_path);
        xsetenv("PATH", new_path);
        free(new_path);
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