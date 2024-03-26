/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <fcntl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>

#include "../supercall.h"
#include "android_user.h"

#define PKG_NAME_LEN 256

struct allow_pkg_info
{
    const char pkg[PKG_NAME_LEN];
    uid_t uid;
    uid_t to_uid;
    const char sctx[SUPERCALL_SCONTEXT_LEN];
};

static char magiskpolicy_path[] = APATCH_BIN_FLODER "magiskpolicy";
static char pkg_cfg_path[] = APATCH_FLODER "package_config";
static char su_path_path[] = APATCH_FLODER "su_path";

extern const char *key;
static bool from_kernel = false;

static char *trim(char *p)
{
    if (!p || !p[0]) return p;

    while (isspace(*p))
        p++;

    char *e = p + strlen(p) - 1;
    while (e > p && isspace(*e))
        *e-- = '\0';
    return p;
}

static int log_kernel(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return sc_klog(key, buf);
}

static char *csv_val(const char *header, const char *line, const char *key)
{
    const char *kpos = strstr(header, key);
    if (!kpos) return 0;
    int kidx = 0;
    const char *c = 0;
    for (c = header; c < kpos; c++) {
        if (*c == ',') kidx++;
    }
    for (c = line; kidx; c++) {
        if (*c == ',') kidx--;
    }
    const char *e = c;
    for (; *e && *e != ','; e++) {
    };

    return strndup(c, e - c);
}

static void load_config_allow_uids()
{
    char linebuf[1024], header[1024] = { '\0' };
    char *line = 0;

    FILE *fallow = fopen(pkg_cfg_path, "r");
    if (fallow == NULL) {
        log_kernel("%d open %s error: %s\n", getpid(), pkg_cfg_path, strerror(errno));
        return;
    }

    // remove defualt if this function is called from kernel and the file is existed
    if (from_kernel) sc_su_revoke_uid(key, 2000);

    fgets(header, sizeof(header) - 1, fallow);
    if (!strlen(header)) goto out;

    while ((line = fgets(linebuf, sizeof(linebuf) - 1, fallow))) {
        line = trim(line);
        if (!line || line[0] == '#') continue;
        log_kernel("pkg config line: %s\n", line);

        char *sallow = csv_val(header, line, "allow");
        if (!sallow) continue;

        if (!atol(sallow)) {
            free(sallow);
            continue;
        }

        char *spkg = csv_val(header, line, "pkg");
        char *suid = csv_val(header, line, "uid");
        char *sto_uid = csv_val(header, line, "to_uid");
        char *ssctx = csv_val(header, line, "sctx");

        if (!spkg || !suid || !sto_uid || !ssctx) continue;

        log_kernel("grant pkg: %s, uid: %s, to_uid: %s, sctx: %s\n", spkg, suid, sto_uid, ssctx);

        uid_t to_uid = atol(sto_uid);
        struct su_profile profile = { 0 };
        profile.uid = atol(suid);
        profile.to_uid = to_uid;
        if (ssctx) strncpy(profile.scontext, ssctx, sizeof(profile.scontext) - 1);

        sc_su_grant_uid(key, profile.uid, &profile);

        free(spkg);
        free(suid);
        free(sto_uid);
        free(ssctx);
    }

out:
    fclose(fallow);
}

static void load_config_su_path()
{
    FILE *file = fopen(su_path_path, "rb");
    if (file == NULL) {
        log_kernel("%d open %s error: %s\n", getpid(), su_path_path, strerror(errno));
        return;
    }
    char linebuf[SU_PATH_MAX_LEN] = { '\0' };
    char *path = fgets(linebuf, sizeof(linebuf), file);
    if (path) path = trim(path);
    if (path) sc_su_reset_path(key, path);
    fclose(file);
}

static void fork_for_result(const char *exec, char *const *argv)
{
    char cmd[4096] = { '\0' };
    for (int i = 0;; i++) {
        if (!argv[i]) break;
        strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 1);
        strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
    }

    pid_t pid = fork();
    if (pid < 0) {
        log_kernel("%d fork %s error: %d\n", getpid(), exec, pid);
    } else if (pid == 0) {
        setenv("KERNELPATCH", "true", 1);
        char kpver[16] = { '\0' }, kver[16] = { '\0' };
        sprintf(kpver, "%x", sc_kp_ver(key));
        setenv("KERNELPATCH_VERSION", kpver, 1);
        sprintf(kver, "%x", sc_k_ver(key));
        setenv("KERNEL_VERSION", kver, 1);
        setenv("SUPERKEY", key, 1);
        int rc = execv(exec, argv);
        log_kernel("%d exec %s error: %s\n", getpid(), cmd, strerror(errno));
    } else {
        int status;
        wait(&status);
        log_kernel("%d wait %s status: 0x%x\n", getpid(), cmd, status);
    }
}

static void save_log(char **argv, const char *file)
{
    pid_t pid = fork();

    if (pid < 0) {
        log_kernel("%d fork for dmesg error: %d\n", getpid(), pid);
    } else if (pid == 0) {
        int fd = open(file, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);
        int rc = execv(argv[0], argv);
        log_kernel("%d save log > %s error: %s\n", getpid(), file, strerror(errno));
    } else {
        int status;
        wait(&status);
        log_kernel("%d save log status: 0x%x\n", getpid(), status);
    }
}

static void save_dmegs(const char *file)
{
    char *dmesg_argv[] = {
        "/system/bin/dmesg",
        NULL,
    };
    save_log(dmesg_argv, file);
}

static void early_init()
{
    struct su_profile profile = { .uid = getuid() };
    sc_su(key, &profile);

    log_kernel("%d starting android user early-init\n", getpid());

    save_dmegs(EARLY_INIT_LOG_0);

    // todo:

    save_dmegs(EARLY_INIT_LOG_1);
}

static void post_fs_data_init()
{
    struct su_profile profile = { .uid = getuid() };
    sc_su(key, &profile);

    char current_exe[256] = { '\0' };
    readlink("/proc/self/exe", current_exe, sizeof(current_exe) - 1);

    log_kernel("%d starting android user post-fs-data-init, exec: %s\n", getpid(), current_exe);

    if (!strcmp(current_exe, KPATCH_DEV_PATH)) {
        char *const args[] = { "/system/bin/cp", "-f", current_exe, KPATCH_DATA_PATH, NULL };
        fork_for_result(args[0], args);
        return;
    }

    if (access(APATCH_FLODER, F_OK)) mkdir(APATCH_FLODER, 0700);
    if (access(APATCH_LOG_FLODER, F_OK)) mkdir(APATCH_LOG_FLODER, 0700);

    char *log_args[] = { "/system/bin/cp", "-f", EARLY_INIT_LOG_0, APATCH_LOG_FLODER, NULL };
    fork_for_result(log_args[0], log_args);

    log_args[2] = EARLY_INIT_LOG_1;
    fork_for_result(log_args[0], log_args);

    char *argv[] = { magiskpolicy_path, "--magisk", "--live", NULL };
    fork_for_result(magiskpolicy_path, argv);

    load_config_su_path();
    load_config_allow_uids();

    // load modules

    log_kernel("%d finished android user post-fs-data-init.\n", getpid());
}

static struct option const longopts[] = {
    { "kernel", no_argument, NULL, 'k' },
    { NULL, 0, NULL, 0 },
};

int android_user(int argc, char **argv)
{
    if (!sc_ready(key)) return -EFAULT;

    char *scmd = argv[1];
    if (scmd == NULL) return -EINVAL;

    int optc;
    while ((optc = getopt_long(argc, argv, "k", longopts, NULL)) != -1) {
        switch (optc) {
        case 'k':
            from_kernel = true;
            break;
        default:
            break;
        }
    }

    if (!strcmp("early-init", scmd)) {
        early_init();
    } else if (!strcmp("post-fs-data-init", scmd)) {
        post_fs_data_init();
    } else if (!strcmp("post-fs-data", scmd) || !strcmp("services", scmd) || !strcmp("boot-completed", scmd)) {
        // todo: move to apd
        struct su_profile profile = {
            .uid = getuid(),
            .to_uid = 0,
            .scontext = ALL_ALLOW_SCONTEXT,
        };
        sc_su(key, &profile);

        char *apd_argv[] = {
            APD_PATH,
            scmd,
            NULL,
        };

        fork_for_result(APD_PATH, apd_argv);

        if (access(APATCH_LOG_FLODER, F_OK)) mkdir(APATCH_LOG_FLODER, 0700);

        char log_path[256] = { '\0' };

        sprintf(log_path, APATCH_LOG_FLODER "trigger_%s.dmesg.log", scmd);
        save_dmegs(log_path);

    } else {
        log_kernel("invalid android user cmd: %s\n", scmd);
    }

    return 0;
}