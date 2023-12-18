#include "kpatch.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/capability.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

#include "supercall.h"

uint32_t version()
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return version_code;
}

uint32_t hello(const char *key)
{
    long ret = sc_hello(key);
    if (ret == SUPERCALL_HELLO_MAGIC) {
        fprintf(stdout, "%s\n", SUPERCALL_HELLO_ECHO);
        ret = 0;
    }
    return (uint32_t)ret;
}

int log_kernel(const char *key, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return sc_klog(key, buf);
}

uint32_t kpv(const char *key)
{
    long kpv = sc_kp_version(key);
    if (kpv < 0) return kpv;
    fprintf(stdout, "%x\n", (uint32_t)kpv);
    return 0;
}

int su_thread(const char *key, uid_t uid, uid_t to_uid, const char *sctx)
{
    // return sc_su_task(key, uid, to_uid, sctx);
    return 0;
}

int kpm_load(const char *key, const char *path, const char *args)
{
    int rc = sc_kpm_load(key, path, args);
    return rc;
}

int kpm_unload(const char *key, const char *name)
{
    int rc = sc_kpm_unload(key, name);
    return rc;
}

int kpm_nums(const char *key)
{
    int nums = sc_kpm_nums(key);
    fprintf(stdout, "%d\n", nums);
    return 0;
}

int kpm_list(const char *key)
{
    char buf[4096];
    int rc = sc_kpm_list(key, buf, sizeof(buf));
    if (rc > 0) {
        fprintf(stdout, "%s", buf);
        return 0;
    }
    return rc;
}

int kpm_info(const char *key, const char *name)
{
    char buf[1024];
    int rc = sc_kpm_info(key, name, buf, sizeof(buf));
    if (rc > 0) {
        fprintf(stdout, "%s\n", buf);
        return 0;
    }
    return rc;
}

int __test(const char *key)
{
    return __sc_test(key);
}

int su_grant(const char *key, uid_t uid, uid_t to_uid, const char *scontext)
{
    struct su_profile profile = { 0 };
    profile.uid = uid;
    profile.to_uid = to_uid;
    if (scontext) {
        strncpy(profile.scontext, scontext, sizeof(profile.scontext) - 1);
    }
    profile.scontext[sizeof(profile.scontext) - 1] = '\0';
    int rc = sc_su_grant_uid(key, uid, &profile);
    return rc;
}

int su_revoke(const char *key, uid_t uid)
{
    int rc = sc_su_revoke_uid(key, uid);
    return rc;
}

int su_nums(const char *key)
{
    int nums = sc_su_uid_nums(key);
    fprintf(stdout, "%d\n", nums);
    return 0;
}

int su_list(const char *key)
{
    int nums = sc_su_uid_nums(key);
    uid_t uids[nums];
    int rc = sc_su_allow_uids(key, uids, nums);
    if (rc > 0) {
        for (int i = 0; i < rc; i++) {
            fprintf(stdout, "%d\n", uids[i]);
        }
        return 0;
    }
    return rc;
}

int su_profile(const char *key, uid_t uid)
{
    struct su_profile profile = { 0 };
    long rc = sc_su_uid_profile(key, (uid_t)uid, &profile);
    if (rc < 0) return rc;
    fprintf(stdout, "uid: %d, to_uid: %d, scontext: %s\n", profile.uid, profile.to_uid, profile.scontext);
    return 0;
}

int su_reset_path(const char *key, const char *path)
{
    int rc = sc_su_reset_path(key, path);
    return rc;
}

int su_get_path(const char *key)
{
    char buf[SU_PATH_MAX_LEN];
    int rc = sc_su_get_path(key, buf, sizeof(buf));
    if (rc > 0) {
        fprintf(stdout, "%s\n", buf);
        return 0;
    }
    return rc;
}

#define PKG_NAME_LEN 256

struct allow_pkg_info
{
    const char pkg[PKG_NAME_LEN];
    uid_t uid;
    uid_t to_uid;
    const char sctx[SUPERCALL_SCONTEXT_LEN];
};

#ifdef ANDROID

#include <fcntl.h>
#include <sys/wait.h>
#include <dirent.h>

#define ADB_FLODER "/data/adb/"
#define APATCH_FLODER "/data/adb/ap/"
#define APATCH_BIN_FLODER "/data/adb/ap/bin/"
#define APATCH_LOG_FLODER "/data/adb/ap/log/"

static char magiskpolicy_path[] = APATCH_BIN_FLODER "magiskpolicy";
static char allow_uids_path[] = APATCH_FLODER ".allow_uid";
static char su_path_path[] = APATCH_FLODER ".su_path";

static char boot0_log_path[] = ADB_FLODER ".kpatch_0.log";
static char boot1_log_path[] = APATCH_LOG_FLODER ".kpatch_1.log";
static char boot2_log_path[] = APATCH_LOG_FLODER ".kpatch_2.log";

char *strip(char *str)
{
    char *end;
    while (isspace((unsigned char)*str))
        str++;
    if (!*str) return str;
    end = str + strlen(str);
    while (end > str && isspace((unsigned char)*end))
        end--;
    *end = '\0';
    return str;
}

static void save_dmegs(const char *key, const char *file)
{
    char *dmesg_argv[] = {
        "/system/bin/dmesg",
        NULL,
    };
    pid_t pid = fork();

    if (pid < 0) {
        log_kernel(key, "%d fork for dmesg error: %d\n", getpid(), pid);
    } else if (pid == 0) {
        int fd = open(file, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);
        int rc = execv(dmesg_argv[0], dmesg_argv);
        log_kernel(key, "%d exec dmesg > %s error: %s\n", getpid(), file, strerror(errno));
    } else {
        int status;
        wait(&status);
        log_kernel(key, "%d wait dmesg status: 0x%x\n", getpid(), status);
    }
}

static void load_config_allow_uids(const char *key)
{
    bool should_remove_default = false;
    char linebuf[256];
    char *line = 0;

    FILE *fallow = fopen(allow_uids_path, "r");
    if (fallow == NULL) {
        log_kernel(key, "%d open %s error: %s", getpid(), allow_uids_path, strerror(errno));
        return;
    }

    while ((line = fgets(linebuf, sizeof(linebuf), fallow))) {
        line = strip(line);
        if (!line || line[0] == '#') continue;

        int len = strlen(line);
        for (int i = 0; i < len; i++) {
            if (isspace(line[i]) || line[i] == ':') line[i] = '\0';
        }

        char *split[4] = { 0 };
        int j = 0;
        for (int i = 0; i < len; i++) {
            if (line[i]) {
                split[j++] = line + i;
                while (line[++i])
                    ;
            }
        }

        const char *pkg = split[0];
        const char *suid = split[1];
        const char *sto_uid = split[2];
        const char *sctx = split[3];
        if (!pkg || !suid || !sto_uid) continue;

        uid_t uid = atol(suid);
        uid_t to_uid = atol(sto_uid);
        struct su_profile profile = { 0 };
        profile.uid = uid;
        profile.to_uid = to_uid;
        if (sctx) strncpy(profile.scontext, sctx, sizeof(profile.scontext) - 1);

        sc_su_grant_uid(key, uid, &profile);

        if (uid != 2000) should_remove_default = true;
    }

    fclose(fallow);

    if (should_remove_default) {
        sc_su_revoke_uid(key, 2000);
    }
}

static void load_config_su_path(const char *key)
{
    FILE *file = fopen(su_path_path, "rb");
    if (file == NULL) {
        log_kernel(key, "%d open %s error: %s", getpid(), su_path_path, strerror(errno));
        return;
    }
    char buf[15] = { '\0' };
    int rl = fread(buf, 1, sizeof(buf), file);
    if (rl > 0) sc_su_reset_path(key, buf);
    fclose(file);
}

static void load_magisk_policy(const char *key)
{
    pid_t pid = fork();
    if (pid < 0) {
        log_kernel(key, "%d fork for magiskpolicy error: %d\n", getpid(), pid);
    } else if (pid == 0) {
        char *argv[] = {
            magiskpolicy_path,
            "--magisk",
            "--live",
            NULL,
        };
        int rc = execv(argv[0], argv);
        log_kernel(key, "%d exec magiskpolicy error %s\n", getpid(), strerror(errno));
    } else {
        int status;
        wait(&status);
        log_kernel(key, "%d wait magiskpolicy status: 0x%x\n", getpid(), status);
    }
}

int android_user_init(const char *key)
{
    // check kernel_patch
    if (!sc_ready(key)) return -EFAULT;

    struct su_profile profile = { 0 };
    profile.uid = getuid();
    sc_su(key, &profile);

    save_dmegs(key, boot0_log_path);

    // create floder is not exist, but in actually, apatch is not installed
    if (!opendir(APATCH_FLODER)) mkdir(APATCH_FLODER, 0700);
    if (!opendir(APATCH_BIN_FLODER)) mkdir(APATCH_BIN_FLODER, 0700);
    if (!opendir(APATCH_LOG_FLODER)) mkdir(APATCH_LOG_FLODER, 0700);

    log_kernel(key, "%d starting android user init ...\n", getpid());

    load_config_su_path(key);
    load_config_allow_uids(key);
    load_magisk_policy(key);

    save_dmegs(key, boot1_log_path);

    fprintf(stdout, "%d finished android user init.\n", getpid());
    return 0;
}

#endif