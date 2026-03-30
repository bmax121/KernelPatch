/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm-generic/compat.h>
#include <uapi/asm-generic/errno.h>
#include <syscall.h>
#include <symbol.h>
#include <kconfig.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <taskob.h>
#include <predata.h>
#include <accctl.h>
#include <asm/current.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <syscall.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <predata.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/umh.h>
#include <uapi/scdefs.h>
#include <uapi/linux/stat.h>
#include <sucompat.h>
#include <userd.h>
#include <uapi/linux/limits.h>

#define REPLACE_RC_FILE "/dev/user_init.rc"

#define ADB_FLODER "/data/adb/"
#define AP_DIR "/data/adb/ap/"
#define DEV_LOG_DIR "/dev/user_init_log/"
#define AP_BIN_DIR AP_DIR "bin/"
#define AP_LOG_DIR AP_DIR "log/"
#define AP_MAGISKPOLICY_PATH AP_BIN_DIR "magiskpolicy"
#define MAGISK_SCTX "u:r:magisk:s0"
#define APD_PATH "/data/adb/apd"
#define MAGISK_POLICY_PATH "/data/adb/ap/bin/magiskpolicy"
#define AP_PACKAGE_CONFIG_PATH "/data/adb/ap/package_config"



static const char ORIGIN_RC_FILES[][64] = {
    "/system/etc/init/hw/init.rc",
    "/init.rc",
    "/vendor/etc/init/hw/init.target.rc",
    ""
};

static const char user_rc_data[] = { //
    "\n"
    "on early-init\n"
    "    exec -- " SUPERCMD " %s event early-init before\n"
    "on init\n"
    "    exec -- " SUPERCMD " %s event init before\n"
    "on late-init\n"
    "    exec -- " SUPERCMD " %s event late-init before\n"
    "on post-fs-data\n"
    "    exec -- " SUPERCMD " su -Z " MAGISK_SCTX " exec " MAGISK_POLICY_PATH " --magisk --live\n"
    "    exec -- " SUPERCMD " su -Z " MAGISK_SCTX " exec " APD_PATH " -s %s post-fs-data\n"
    "on nonencrypted\n"
    "    exec -- " SUPERCMD " su -Z " MAGISK_SCTX " exec " APD_PATH " -s %s services\n"
    "on property:vold.decrypt=trigger_restart_framework\n"
    "    exec -- " SUPERCMD " su -Z " MAGISK_SCTX " exec " APD_PATH " -s %s services\n"
    "on property:sys.boot_completed=1\n"
    "    exec -- " SUPERCMD " su -Z " MAGISK_SCTX " exec " APD_PATH " -s %s boot-completed\n"
    "    exec -- " SUPERCMD " su -Z " MAGISK_SCTX " exec " APD_PATH " uid-listener &\n"
    "    rm " REPLACE_RC_FILE "\n"
    "    exec -- " SUPERCMD " su -Z " MAGISK_SCTX " -c \"mv -f " DEV_LOG_DIR " " AP_LOG_DIR "\"\n"
    ""
};

static const void *kernel_read_file(const char *path, loff_t *len)
{
    set_priv_sel_allow(current, true);
    void *data = 0;

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
        log_boot("open file: %s error: %d\n", path, PTR_ERR(filp));
        goto out;
    }
    *len = vfs_llseek(filp, 0, SEEK_END);
    vfs_llseek(filp, 0, SEEK_SET);
    data = vmalloc(*len);
    loff_t pos = 0;
    kernel_read(filp, data, *len, &pos);
    filp_close(filp, 0);

out:
    set_priv_sel_allow(current, false);
    return data;
}

static loff_t kernel_write_file(const char *path, const void *data, loff_t len, umode_t mode)
{
    loff_t off = 0;
    set_priv_sel_allow(current, true);

    struct file *fp = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (!fp || IS_ERR(fp)) {
        log_boot("create file %s error: %d\n", path, PTR_ERR(fp));
        goto out;
    }
    kernel_write(fp, data, len, &off);
    if (off != len) {
        log_boot("write file %s error: %x\n", path, off);
        goto free;
    }

free:
    filp_close(fp, 0);

out:
    set_priv_sel_allow(current, false);
    return off;
}

// Simple CSV field parser helper function
static char *parse_csv_field(char **line_ptr)
{
    char *start = *line_ptr;
    char *end = start;

    if (!start || *start == '\0') return NULL;

    // Skip leading whitespace
    while (*start == ' ' || *start == '\t') start++;

    // Find comma or end of line
    end = start;
    while (*end && *end != ',' && *end != '\n' && *end != '\r') {
        end++;
    }

    // Preserve delimiter before modifying buffer
    {
        char delim = *end;

        // Remove trailing whitespace only if field is non-empty
        if (end > start) {
            char *trim_end = end - 1;
            while (trim_end > start && (*trim_end == ' ' || *trim_end == '\t')) {
                trim_end--;
            }
            *(trim_end + 1) = '\0';
        } else {
            // Empty field: terminate at start so caller sees an empty string
            *start = '\0';
        }

        // Update pointer position based on original delimiter
        if (delim == ',') {
            *line_ptr = end + 1;
        } else {
            *line_ptr = end;
        }
    }

    return start;
}

// Load APatch package_config configuration file
// Returns: number of entries loaded, or negative error code
int load_ap_package_config()
{
    loff_t len = 0;
    const char *data = kernel_read_file(AP_PACKAGE_CONFIG_PATH, &len);

    if (!data || len <= 0) {
        log_boot("package_config not found or empty\n");
        return -ENOENT;
    }
    if (len > 10 * 1024 * 1024){
        log_boot("package_config too large: %lld\n", len);
        return -EFBIG;
    }

    log_boot("loading package_config, size: %lld\n", len);

    char *content = (char *)data;
    char *line_start = content;
    int line_num = 0;
    int loaded_count = 0;
    int skipped_count = 0;

    // Parse CSV line by line
    while (line_start < content + len) {
        char *line_end = line_start;
        int has_newline = 0;

        // Find end of line
        while (line_end < content + len && *line_end != '\n' && *line_end != '\r') {
            line_end++;
        }

        // Check if we found a newline
        if (line_end < content + len) {
            has_newline = 1;
            *line_end = '\0';  // Safe because line_end < content + len
        }

        line_num++;

        // Skip CSV header
        if (line_num == 1) {
            if (has_newline) {
                line_start = line_end + 1;
            } else {
                break;
            }
            continue;
        }

        // Process current line
        char *line_ptr = line_start;
        int valid_line = 1;

        // Parse CSV fields: pkg,exclude,allow,uid,to_uid,sctx
        parse_csv_field(&line_ptr); // skip pkg field
        char *exclude_str = parse_csv_field(&line_ptr);
        char *allow_str = parse_csv_field(&line_ptr);
        char *uid_str = parse_csv_field(&line_ptr);
        char *to_uid_str = parse_csv_field(&line_ptr);
        char *sctx = parse_csv_field(&line_ptr);

        // Check required fields
        if (!uid_str || !to_uid_str || !sctx) {
            log_boot("package_config: line %d missing required fields (uid/to_uid/sctx)\n", line_num);
            valid_line = 0;
            goto next_line;
        }

        unsigned long long uid_tmp = 0, to_uid_tmp = 0;
        unsigned long long exclude_tmp = 0, allow_tmp = 0;
        int ret;

        // Convert UID fields - must succeed
        ret = kstrtoull(uid_str, 10, &uid_tmp);
        if (ret) {
            log_boot("package_config: line %d invalid uid '%s': %d\n", line_num, uid_str, ret);
            valid_line = 0;
            goto next_line;
        }

        ret = kstrtoull(to_uid_str, 10, &to_uid_tmp);
        if (ret) {
            log_boot("package_config: line %d invalid to_uid '%s': %d\n", line_num, to_uid_str, ret);
            valid_line = 0;
            goto next_line;
        }

        // Range check for uid_t (typically unsigned int)
        if (uid_tmp > UINT_MAX) {
            log_boot("package_config: line %d uid %llu out of range\n", line_num, uid_tmp);
            valid_line = 0;
            goto next_line;
        }
        if (to_uid_tmp > UINT_MAX) {
            log_boot("package_config: line %d to_uid %llu out of range\n", line_num, to_uid_tmp);
            valid_line = 0;
            goto next_line;
        }

        // Convert optional fields (exclude and allow)
        if (exclude_str && *exclude_str) {
            ret = kstrtoull(exclude_str, 10, &exclude_tmp);
            if (ret) {
                log_boot("package_config: line %d invalid exclude '%s': %d, using default 0\n", 
                         line_num, exclude_str, ret);
                exclude_tmp = 0;
            }
            if (exclude_tmp > INT_MAX) {
                log_boot("package_config: line %d exclude %llu out of range, clamping\n", 
                         line_num, exclude_tmp);
                exclude_tmp = INT_MAX;
            }
        }

        if (allow_str && *allow_str) {
            ret = kstrtoull(allow_str, 10, &allow_tmp);
            if (ret) {
                log_boot("package_config: line %d invalid allow '%s': %d, using default 0\n", 
                         line_num, allow_str, ret);
                allow_tmp = 0;
            }
            if (allow_tmp > INT_MAX) {
                log_boot("package_config: line %d allow %llu out of range, clamping\n", 
                         line_num, allow_tmp);
                allow_tmp = INT_MAX;
            }
        }

        uid_t uid = (uid_t)uid_tmp;
        uid_t to_uid = (uid_t)to_uid_tmp;
        int exclude = (int)exclude_tmp;
        int allow = (int)allow_tmp;

        // Validate sctx is not empty
        if (!sctx || !*sctx) {
            log_boot("package_config: line %d empty sctx\n", line_num);
            valid_line = 0;
            goto next_line;
        }

        // CRITICAL FIX: Safely copy sctx into a fixed-size buffer with NUL termination
        // This prevents buffer overflow and ensures proper string handling
        char sctx_buf[SUPERCALL_SCONTEXT_LEN];
        size_t sctx_len = strlen(sctx);
        
        if (sctx_len >= SUPERCALL_SCONTEXT_LEN) {
            // Truncate and log warning
            log_boot("package_config: line %d sctx too long (%zu bytes), truncating to %d bytes\n",
                     line_num, sctx_len, SUPERCALL_SCONTEXT_LEN - 1);
            memcpy(sctx_buf, sctx, SUPERCALL_SCONTEXT_LEN - 1);
            sctx_buf[SUPERCALL_SCONTEXT_LEN - 1] = '\0';
        } else {
            // Safe copy with NUL termination
            memcpy(sctx_buf, sctx, sctx_len + 1);  // +1 includes the NUL terminator
        }

        // Apply configuration with safe sctx buffer
        if (allow) {
            int rc = su_add_allow_uid(uid, to_uid, sctx_buf);
            if (rc == 0) {
                loaded_count++;
            } else {
                log_boot("package_config: line %d failed to add allow rule: %d\n", line_num, rc);
                valid_line = 0;
            }
        }

        // Set exclude flag
        if (exclude) {
            set_ap_mod_exclude(uid, exclude);
        }

next_line:
        if (!valid_line) {
            skipped_count++;
        }

        // Move to next line
        if (has_newline) {
            line_start = line_end + 1;
        } else {
            break;
        }
    }

    kvfree(data);
    log_boot("package_config loaded: %d entries, skipped: %d\n", loaded_count, skipped_count);
    return loaded_count;
}
KP_EXPORT_SYMBOL(load_ap_package_config);

static void pre_user_exec_init()
{
    log_boot("event: %s\n", EXTRA_EVENT_PRE_EXEC_INIT);

}

static void pre_init_second_stage()
{
    log_boot("event: %s\n", EXTRA_EVENT_PRE_SECOND_STAGE);

}

static void on_first_app_process()
{
}

static void handle_before_execve(hook_local_t *hook_local, char **__user u_filename_p, char **__user uargv,
                                 char **__user uenvp, void *udata)
{
    // unhook flag
    hook_local->data7 = 0;

    static char app_process[] = "/system/bin/app_process";
    static char app_process64[] = "/system/bin/app_process64";
    static int first_app_process_execed = 0;

    static const char system_bin_init[] = "/system/bin/init";
    static const char root_init[] = "/init";
    static int first_user_init_executed = 0;
    static int init_second_stage_executed = 0;

    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(system_bin_init, filename) || !strcmp(root_init, filename)) {
        //
        if (!first_user_init_executed) {
            first_user_init_executed = 1;
            log_boot("exec first user init: %s\n", filename);
            pre_user_exec_init();
        }

        if (!init_second_stage_executed) {
            for (int i = 1;; i++) {
                const char __user *p1 = get_user_arg_ptr(0, *uargv, i);
                if (!p1 || IS_ERR(p1)) break;

                char arg[16] = { '\0' };
                if (compat_strncpy_from_user(arg, p1, sizeof(arg)) <= 0) break;

                if (!strcmp(arg, "second_stage") || !strcmp(arg, "--second-stage")) {
                    log_boot("exec %s second stage 0\n", filename);
                    pre_init_second_stage();
                    init_second_stage_executed = 1;
                }
            }
        }

        if (!init_second_stage_executed) {
            for (int i = 0;; i++) {
                const char *__user uenv = get_user_arg_ptr(0, *uenvp, i);
                if (!uenv || IS_ERR(uenv)) break;

                char env[256];
                if (compat_strncpy_from_user(env, uenv, sizeof(env)) <= 0) break;
                char *env_name = env;
                char *env_value = strchr(env, '=');
                if (env_value) {
                    *env_value = '\0';
                    env_value++;
                    if (!strcmp(env_name, "INIT_SECOND_STAGE") &&
                        (!strcmp(env_value, "1") || !strcmp(env_value, "true"))) {
                        log_boot("exec %s second stage 1\n", filename);
                        pre_init_second_stage();
                        init_second_stage_executed = 1;
                    }
                }
            }
        }
    }

    if (!first_app_process_execed && (!strcmp(app_process, filename) || !strcmp(app_process64, filename))) {
        first_app_process_execed = 1;
        log_boot("exec first app_process: %s\n", filename);
        on_first_app_process();
        hook_local->data7 = 1;
        return;
    }
}

static void before_execve(hook_fargs3_t *args, void *udata);
static void after_execve(hook_fargs3_t *args, void *udata);
static void before_execveat(hook_fargs5_t *args, void *udata);
static void after_execveat(hook_fargs5_t *args, void *udata);

static void handle_after_execve(hook_local_t *hook_local)
{
    int unhook = hook_local->data7;
    if (unhook) {
        unhook_syscalln(__NR_execve, before_execve, after_execve);
        unhook_syscalln(__NR_execveat, before_execveat, after_execveat);
    }
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2087
// SYSCALL_DEFINE3(execve, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp)
static void before_execve(hook_fargs3_t *args, void *udata)
{
    void *arg0p = syscall_argn_p(args, 0);
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    handle_before_execve(&args->local, (char **)arg0p, (char **)arg1p, (char **)arg2p, udata);
}

static void after_execve(hook_fargs3_t *args, void *udata)
{
    handle_after_execve(&args->local);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2095
// SYSCALL_DEFINE5(execveat, int, fd, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp, int, flags)
static void before_execveat(hook_fargs5_t *args, void *udata)
{
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    void *arg3p = syscall_argn_p(args, 3);
    handle_before_execve(&args->local, (char **)arg1p, (char **)arg2p, (char **)arg3p, udata);
}

static void after_execveat(hook_fargs5_t *args, void *udata)
{
    handle_after_execve(&args->local);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/open.c#L1337
// SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, umode_t, mode)
static void before_openat(hook_fargs4_t *args, void *udata)
{
    
    // cp len
    args->local.data0 = 0;
    // cp ptr
    args->local.data1 = 0;
    // unhook flag
    args->local.data2 = 0;
    /* Meaning of args->local.data3 values:
     * 0 = no match
     * 1 = ORIGIN_RC_FILES[0]
     * 2 = ORIGIN_RC_FILES[1]
     */
    args->local.data3 = 0;
    static int replaced = 0;
    if (replaced) return;

    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[64];
    long rc = compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (rc <= 0) return;

    int file_count = sizeof(ORIGIN_RC_FILES) / sizeof(ORIGIN_RC_FILES[0]);
    for (int i = 0; i < file_count; i++) {
        if (ORIGIN_RC_FILES[i][0] == '\0') break;
        
        if (!strcmp(buf, ORIGIN_RC_FILES[i])) {
            args->local.data3 = i + 1;
            log_boot("matched rc file: %s\n", ORIGIN_RC_FILES[i]);
            break;
        }
    }

    if (args->local.data3 == 0) {
        return;
    }

    replaced = 1;
    const char *origin_rc = ORIGIN_RC_FILES[args->local.data3 - 1];

    loff_t ori_len = 0;
    struct file *newfp = filp_open(REPLACE_RC_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (!newfp || IS_ERR(newfp)) {
        log_boot("create replace rc error: %d\n", PTR_ERR(newfp));
        goto out;
    }

    loff_t off = 0;
    const char *ori_rc_data = kernel_read_file(origin_rc, &ori_len);
    if (!ori_rc_data) goto out;
    kernel_write(newfp, ori_rc_data, ori_len, &off);
    if (off != ori_len) {
        log_boot("write replace rc error: %x\n", off);
        goto free;
    }

    char added_rc_data[4096];
    const char *sk = get_superkey();
    sprintf(added_rc_data, user_rc_data, sk, sk, sk, sk, sk, sk, sk);

    kernel_write(newfp, added_rc_data, strlen(added_rc_data), &off);
    if (off != strlen(added_rc_data) + ori_len) {
        log_boot("write replace rc error: %x\n", off);
        goto free;
    }

    int cplen = 0;
    cplen = compat_copy_to_user((void *)filename, REPLACE_RC_FILE, sizeof(REPLACE_RC_FILE));
    if (cplen > 0) {
        args->local.data0 = cplen;
        args->local.data1 = (uint64_t)args->arg1;
        log_boot("redirect rc file: %x\n", args->local.data0);
    } else {
        void *__user up = copy_to_user_stack(REPLACE_RC_FILE, sizeof(REPLACE_RC_FILE));
        args->arg1 = (uint64_t)up;
        log_boot("redirect rc file stack: %llx\n", up);
    }

free:
    filp_close(newfp, 0);
    kvfree(ori_rc_data);

out:
    args->local.data2 = 1;
    return;
}

static void after_openat(hook_fargs4_t *args, void *udata)
{
 
    if (args->local.data0 && args->local.data3 > 0) {
        
        const char *origin_rc = ORIGIN_RC_FILES[args->local.data3 - 1];
        compat_copy_to_user(
            (void *)args->local.data1,
            origin_rc,
            sizeof(ORIGIN_RC_FILES[args->local.data3 - 1]));
        log_boot("restore rc file: %x\n", args->local.data0);
    }

    
    if (args->local.data2) {
        unhook_syscalln(__NR_openat, before_openat, after_openat);
    }
}
#define EV_KEY 0x01
#define KEY_VOLUMEDOWN 114

int android_is_safe_mode = 0;
KP_EXPORT_SYMBOL(android_is_safe_mode);

// void input_handle_event(struct input_dev *dev, unsigned int type, unsigned int code, int value)
static void before_input_handle_event(hook_fargs4_t *args, void *udata)
{
    static unsigned int volumedown_pressed_count = 0;
    unsigned int type = args->arg1;
    unsigned int code = args->arg2;
    int value = args->arg3;
    if (value && type == EV_KEY && code == KEY_VOLUMEDOWN) {
        volumedown_pressed_count++;
        if (volumedown_pressed_count == 3) {
            log_boot("entering safemode ...");
            android_is_safe_mode = 1;
        }
    }
}

int android_user_init()
{
    hook_err_t ret = 0;
    hook_err_t rc = HOOK_NO_ERR;

    rc = hook_syscalln(__NR_execve, 3, before_execve, after_execve, (void *)__NR_execve);
    log_boot("hook __NR_execve rc: %d\n", rc);
    ret |= rc;

    rc = hook_syscalln(__NR_execveat, 5, before_execveat, after_execveat, (void *)__NR_execveat);
    log_boot("hook __NR_execveat rc: %d\n", rc);
    ret |= rc;

    rc = hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    log_boot("hook __NR_openat rc: %d\n", rc);
    ret |= rc;

    unsigned long input_handle_event_addr = patch_config->input_handle_event;
    if (input_handle_event_addr) {
        rc = hook_wrap4((void *)input_handle_event_addr, before_input_handle_event, 0, 0);
        ret |= rc;
        log_boot("hook input_handle_event rc: %d\n", rc);
    }

    return ret;
}
