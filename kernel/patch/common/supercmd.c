#include <kputils.h>
#include <stdarg.h>
#include <sucompat.h>
#include <linux/string.h>
#include <linux/syscall.h>
#include <ktypes.h>
#include <stdbool.h>
#include <uapi/scdefs.h>
#include <syscall.h>
#include <predata.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <accctl.h>
#include <linux/slab.h>
#include <module.h>
#include <user_event.h>

static char *__user supercmd_str_to_user_sp(const char *data, uintptr_t *sp)
{
    int len = strlen(data) + 1;
    *sp -= len;
    *sp &= 0xFFFFFFFFFFFFFFF8;
    int cplen = compat_copy_to_user((void *)*sp, data, len);
    if (cplen > 0) return (char *__user) * sp;
    return 0;
}

static void supercmd_exec(char **__user u_filename_p, const char *cmd, uintptr_t *sp)
{
    int cplen = 0;
#if 1
    cplen = compat_copy_to_user(*u_filename_p, cmd, strlen(cmd) + 1);
#endif
    if (cplen <= 0) *u_filename_p = supercmd_str_to_user_sp(cmd, sp);
}

static void supercmd_echo(char **__user u_filename_p, char **__user uargv, uintptr_t *sp, const char *fmt, ...)
{
    supercmd_exec(u_filename_p, ECHO_PATH, sp);

    char buffer[4096];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, va);
    va_end(va);

    const char *__user cmd = supercmd_str_to_user_sp(ECHO_PATH, sp);
    const char *__user argv1 = supercmd_str_to_user_sp(buffer, sp);

    set_user_arg_ptr(0, *uargv, 0, (uintptr_t)cmd);
    set_user_arg_ptr(0, *uargv, 1, (uintptr_t)argv1);
    set_user_arg_ptr(0, *uargv, 2, 0);
}

static const char supercmd_help[] =
    ""
    "KernelPatch supercmd:\n"
    "Usage: truncate <superkey|su> [-uZc] [Command [[SubCommand]...]]\n"
    "superkey|su:                   Authentication.\n"
    "Options:\n"
    "  -u <UID>                     Change user id to UID.\n"
    "  -Z <SCONTEXT>                Change security context to SCONTEXT.\n"
    "\n"
    "Command:\n"
    "  help:                        Print this help message.\n"
    "  version:                     Print Kernel version and KernelPatch version.\n"
    "  buildtime:                   Print KernelPatch build time.\n "
    "    eg: 50a0a,a06 means kernel version 5.10.10, KernelPatch version 0.10.6.\n"
    "  -c <COMMAND> [...]:          Pass a single COMMAND to the default shell.\n"
    "  exec <PATH> [...]:           Execute command with full PATH.\n"
    "  sumgr <SubCommand> [...]:    SU permission manager\n"
    "    The default command obtain a shell with the specified TO_UID and SCONTEXT is 'kp',\n"
    "    whose full PATH is '/system/bin/kp'. This can avoid conflicts with the existing 'su' command.\n"
    "    If you wish to modify this PATH, you can use the 'reset' command.\n"
    "    SubCommand:\n"
    "      grant <UID> [TO_UID [SCONTEXT]]  Grant su permission to UID.\n"
    "      revoke                           Revoke su permission to UID.\n"
    "      num                              Get the number of uids with the aforementioned permissions.\n"
    "      list                             List all su allowed uids.\n"
    "      profile <UID>                    Get the profile of the uid configuration.\n"
    "      path [PATH]                      Get or Reset current su path. The length of PATH must 2-127.\n"
    "      sctx [SCONTEXT]                  Get or Reset current all allowed security context.\n"
#ifdef ANDROID
    "      exclude_list                     List all exclude UIDs.\n"
    "      exclude <UID> [1|0]              Get or Reset exclude policy for UID.\n"
#endif
    "  event <EVENT>                        Report EVENT.\n"
    "\n"
    "The command below requires superkey authentication.\n"
    "  module <SubCommand> [...]:   KernelPatch Module manager\n"
    "    SubCommand:\n"
    "      load <KPM_PATH> [KPM_ARGS]       Load module with KPM_PATH and KPM_ARGS.\n"
    "      ctl0 <KPM_NAME> <CTL_ARGS>       Control module named KPM_PATH with CTL_ARGS.\n"
    "      unload <KPM_NAME>                Unload module named KPM_NAME.\n"
    "      num                              Get the number of modules that have been loaded.\n"
    "      list                             List names of all loaded modules.\n"
    "      info <KPM_NAME>                  Get detailed information about module named KPM_NAME.\n"
    "  key <SubCommand> [...]:      Superkey manager\n"
    "    SubCommand:\n"
    "      key [SUPERKEY]:                  Get or Reset current superkey\n"
    "      hash <enable|disable>:           Whether to use hash to verify the root superkey.\n"
    "";

struct cmd_res
{
    const char *msg;
    const char *err_msg;
    int rc;
};

static void handle_cmd_sumgr(char **__user u_filename_p, const char **carr, char *buffer, int buflen,
                             struct cmd_res *cmd_res)
{
    const char *sub_cmd = carr[1];
    if (!sub_cmd) sub_cmd = "";

    if (!strcmp(sub_cmd, "grant")) {
        unsigned long long uid = 0, to_uid = 0;
        const char *scontext = "";
        if (!carr[2] || kstrtoull(carr[2], 10, &uid)) {
            sprintf(buffer, "illegal uid: %s", carr[2]);
            cmd_res->err_msg = buffer;
            return;
        }
        if (carr[3]) kstrtoull(carr[3], 10, &to_uid);
        if (carr[4]) scontext = carr[4];
        su_add_allow_uid(uid, to_uid, scontext);
        sprintf(buffer, "grant %d, %d, %s", uid, to_uid, scontext);
        cmd_res->msg = buffer;
    } else if (!strcmp(sub_cmd, "revoke")) {
        const char *suid = carr[2];
        unsigned long long uid;
        if (!suid || kstrtoull(suid, 10, &uid)) {
            sprintf(buffer, "illegal uid: %s\n", suid);
            cmd_res->err_msg = buffer;
            return;
        }
        su_remove_allow_uid(uid);
        cmd_res->msg = suid;
    } else if (!strcmp(sub_cmd, "num")) {
        int num = su_allow_uid_nums();
        sprintf(buffer, "%d", num);
        cmd_res->msg = buffer;
    } else if (!strcmp(sub_cmd, "list")) {
        uid_t uids[128]; // default max size 128
        int offset = 0;
        buffer[0] = '\0';
        int num = su_allow_uids(0, uids, sizeof(uids) / sizeof(uids[0]));
        for (int i = 0; i < num; i++) {
            offset += sprintf(buffer + offset, "%d\n", uids[i]);
        };
        if (offset > 0) buffer[offset - 1] = '\0';
        cmd_res->msg = buffer;

    } else if (!strcmp(sub_cmd, "profile")) {
        unsigned long long uid;
        if (!carr[2] || kstrtoull(carr[2], 10, &uid)) {
            cmd_res->err_msg = "invalid uid";
            return;
        }
        struct su_profile profile;
        cmd_res->rc = su_allow_uid_profile(0, uid, &profile);
        if (cmd_res->rc) return;

        sprintf(buffer, "uid: %d, to_uid: %d, scontext: %s", profile.uid, profile.to_uid, profile.scontext);
        cmd_res->msg = buffer;

    } else if (!strcmp(sub_cmd, "path")) {
        if (carr[2]) {
            cmd_res->rc = su_reset_path(carr[2]);
            if (cmd_res->rc) return;
            cmd_res->msg = carr[2];
            carr[2] = 0; // no free
        } else {
            cmd_res->msg = su_get_path();
        }
    } else if (!strcmp(sub_cmd, "sctx")) {
        if (carr[2]) {
            cmd_res->rc = set_all_allow_sctx(carr[2]);
            if (!cmd_res->rc) cmd_res->msg = carr[2];
        } else {
            cmd_res->msg = all_allow_sctx;
        }
    }
#ifdef ANDROID
    else if (!strcmp(sub_cmd, "exclude")) {
        unsigned long long uid;
        if (!carr[2] || kstrtoull(carr[2], 10, &uid)) {
            cmd_res->err_msg = "invalid uid";
            return;
        } else {
            if (!carr[3]) {
                int exclude = get_ap_mod_exclude(uid);
                sprintf(buffer, "%d", exclude);
                cmd_res->msg = buffer;
            } else {
                if (carr[3][0] == '0') {
                    set_ap_mod_exclude(uid, 0);
                    cmd_res->msg = "0";
                } else {
                    set_ap_mod_exclude(uid, 1);
                    cmd_res->msg = "1";
                }
            }
        }
    } else if (!strcmp(sub_cmd, "exclude_list")) {
        uid_t uids[128];
        int offset = 0;
        buffer[0] = '\0';
        int cnt = list_ap_mod_exclude(uids, sizeof(uids) / sizeof(uids[0]));
        if (cnt < 0) {
            cmd_res->rc = cnt;
        } else {
            for (int i = 0; i < cnt; i++) {
                offset += sprintf(buffer + offset, "%d\n", uids[i]);
            };
            if (offset > 0) buffer[offset - 1] = '\0';
            cmd_res->msg = buffer;
        }
    }
#endif
    else {
        cmd_res->err_msg = "invalid subcommand";
    }
}

// superkey commands
static void handle_cmd_key_auth(char **__user u_filename_p, const char *cmd, const char **carr, char *buffer,
                                int buflen, struct cmd_res *cmd_res)
{
    if (!strcmp("key", cmd)) {
        const char *sub_cmd = carr[1];
        if (!sub_cmd) sub_cmd = "";
        if (!strcmp("get", sub_cmd)) {
            cmd_res->msg = get_superkey();
        } else if (!strcmp("set", sub_cmd)) {
            const char *key = carr[2];
            if (!key) {
                cmd_res->err_msg = "invalid new key";
                return;
            }
            cmd_res->msg = key;
            reset_superkey(key);
        } else if (!strcmp("hash", sub_cmd)) {
            const char *able = carr[2];
            if (able && !strcmp("enable", able)) {
                cmd_res->msg = able;
                enable_auth_root_key(true);
            } else if (able && !strcmp("disable", able)) {
                cmd_res->msg = able;
                enable_auth_root_key(false);
            } else {
                cmd_res->err_msg = "invalid enable or disable";
                return;
            }
        } else {
            cmd_res->err_msg = "invalid subcommand";
            return;
        }
    } else if (!strcmp("module", cmd)) {
        const char *sub_cmd = carr[1];
        if (!sub_cmd) sub_cmd = "";
        if (!strcmp("num", sub_cmd)) {
            int num = get_module_nums();
            sprintf(buffer, "%d\n", num);
            cmd_res->msg = buffer;
        } else if (!strcmp("list", sub_cmd)) {
            list_modules(buffer, buflen);
            cmd_res->msg = buffer;
        } else if (!strcmp("load", sub_cmd)) {
            const char *path = carr[2];
            if (!path) {
                cmd_res->err_msg = "invalid module path";
                return;
            }
            cmd_res->rc = load_module_path(path, carr[3], 0);
            if (!cmd_res->rc) cmd_res->msg = path;
        } else if (!strcmp("ctl0", sub_cmd)) {
            const char *name = carr[2];
            if (!name) {
                cmd_res->err_msg = "invalid module name";
                return;
            }
            const char *mod_args = carr[3];
            if (!mod_args) {
                cmd_res->err_msg = "invalid control arguments";
                return;
            }
            buffer[0] = '\0';
            cmd_res->rc = module_control0(name, mod_args, buffer, buflen);
            cmd_res->msg = buffer;
        } else if (!strcmp("ctl1", sub_cmd)) {
            cmd_res->err_msg = "not implement";
        } else if (!strcmp("unload", sub_cmd)) {
            const char *name = carr[2];
            if (!name) {
                cmd_res->err_msg = "invalid module name";
                return;
            }
            cmd_res->rc = unload_module(name, 0);
            if (!cmd_res->rc) cmd_res->msg = name;
        } else if (!strcmp("info", sub_cmd)) {
            const char *name = carr[2];
            if (!name) {
                cmd_res->err_msg = "invalid module name";
                return;
            }
            int sz = get_module_info(name, buffer, buflen);
            if (sz <= 0) cmd_res->rc = sz;
            cmd_res->msg = buffer;
        } else {
            cmd_res->err_msg = "invalid subcommand";
            return;
        }
    } else {
        cmd_res->err_msg = "invalid command";
        return;
    }
}

void handle_supercmd(char **__user u_filename_p, char **__user uargv)
{
    int is_key_auth = 0;

    // key
    const char __user *p1 = get_user_arg_ptr(0, *uargv, 1);
    if (!p1 || IS_ERR(p1)) return;

    struct su_profile profile = { .to_uid = 0, .scontext = "" };

    // auth key
    char arg1[SUPER_KEY_LEN];
    if (compat_strncpy_from_user(arg1, p1, sizeof(arg1)) <= 0) return;

    if (!auth_superkey(arg1)) {
        is_key_auth = 1;
    } else if (!strcmp("su", arg1)) {
        uid_t uid = current_uid();
        if (!is_su_allow_uid(uid)) return;
        su_allow_uid_profile(0, uid, &profile);
    } else {
        return;
    }

#define SUPERCMD_ARGS_NO 16

    // copy args
    const char *parr[SUPERCMD_ARGS_NO + 4] = { 0 };

    for (int i = 2; i < SUPERCMD_ARGS_NO; i++) {
        const char __user *ua = get_user_arg_ptr(0, *uargv, i);
        if (IS_ERR(ua)) break;
        const char *a = strndup_user(ua, 512);
        if (IS_ERR(a)) break;
        parr[i] = a;
        // ignore after -c
        if (a[0] == '-' && a[1] == 'c') break;
    }

    uint64_t sp = current_user_stack_pointer();

    // if no any more
    if (!parr[2]) {
        supercmd_exec(u_filename_p, sh_path, &sp);
        const char *__user argv1 = supercmd_str_to_user_sp(sh_path, &sp);
        set_user_arg_ptr(0, *uargv, 1, (uintptr_t)argv1);
        *uargv += 1 * 8;
        commit_su(profile.to_uid, profile.scontext);
        return;
    }

    int pi = 2;

    // options, contiguous
    while (pi < SUPERCMD_ARGS_NO) {
        const char *arg = parr[pi];
        if (!arg || arg[0] != '-') break;
        // ignore -c
        if (arg[0] == '-' && arg[1] == 'c') break;
        char o = arg[1];
        pi++;
        switch (o) {
        case 'u':
            if (parr[pi]) {
                unsigned long long to_uid = profile.to_uid;
                kstrtoull(parr[pi++], 10, &to_uid);
                profile.to_uid = to_uid;
            } else {
                supercmd_echo(u_filename_p, uargv, &sp, "supercmd error: invalid to_uid");
                goto free;
            }
            break;
        case 'Z':
            if (parr[pi]) {
                strncpy(profile.scontext, parr[pi++], sizeof(profile.scontext) - 1);
                profile.scontext[sizeof(profile.scontext) - 1] = '\0';
            } else {
                supercmd_echo(u_filename_p, uargv, &sp, "supercmd error: invalid scontext\n");
                goto free;
            }
            break;
        default:
            break;
        }
    }

    commit_su(profile.to_uid, profile.scontext);

    struct cmd_res cmd_res = { 0 };

    char buffer[4096];
    buffer[0] = '\0';

    // command
    const char **carr = parr + pi;
    const char *cmd = 0;

    if (pi < SUPERCMD_ARGS_NO - 1) {
        cmd = carr[0];
    } else {
        cmd_res.err_msg = "too many args\n";
        goto echo;
    }

    if (!cmd) {
        supercmd_exec(u_filename_p, sh_path, &sp);
        *uargv += pi * 8;
        goto free;
    }

    if (!strcmp("help", cmd)) {
        cmd_res.msg = supercmd_help;
    } else if (!strcmp("-c", cmd)) {
        supercmd_exec(u_filename_p, sh_path, &sp);
        *uargv += (carr - parr - 1) * 8;
        goto free;
    } else if (!strcmp("exec", cmd)) {
        if (!carr[1]) {
            cmd_res.err_msg = "invalid commmand path";
            goto echo;
        }
        supercmd_exec(u_filename_p, carr[1], &sp);
        *uargv += (carr - parr + 1) * 8;
        goto free;
    } else if (!strcmp("version", cmd)) {
        supercmd_echo(u_filename_p, uargv, &sp, "%x,%x", kver, kpver);
        goto free;
    } else if (!strcmp("buildtime", cmd)) {
        cmd_res.msg = get_build_time();
        goto echo;
    } else if (!strcmp("sumgr", cmd)) {
        handle_cmd_sumgr(u_filename_p, carr, buffer, sizeof(buffer), &cmd_res);
    } else if (!strcmp("event", cmd)) {
        if (carr[1]) {
            cmd_res.rc = report_user_event(carr[1], carr[2]);
            if (!cmd_res.rc) cmd_res.msg = "report success";
        } else {
            cmd_res.err_msg = "empty event";
        }
    } else if (!strcmp("bootlog", cmd)) {
        cmd_res.msg = get_boot_log();
    } else if (!strcmp("test", cmd)) {
        void test();
        test();
        cmd_res.msg = "test done...";
    } else {
        if (is_key_auth) {
            handle_cmd_key_auth(u_filename_p, cmd, carr, buffer, sizeof(buffer), &cmd_res);
        } else {
            cmd_res.err_msg = "invalid command or a superkey is required";
        }
    }

echo:
    if (cmd_res.msg) supercmd_echo(u_filename_p, uargv, &sp, cmd_res.msg);
    if (cmd_res.rc) supercmd_echo(u_filename_p, uargv, &sp, "supercmd error code: %d", cmd_res.rc);
    if (cmd_res.err_msg) supercmd_echo(u_filename_p, uargv, &sp, "supercmd error message: %s", cmd_res.err_msg);

free:
    // free args
    for (int i = 2; i < sizeof(parr) / sizeof(parr[0]); i++) {
        const char *a = parr[i];
        if (!a) continue;
        kfree(a);
    }
}
