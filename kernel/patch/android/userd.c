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
#include <uapi/scdefs.h>
#include <uapi/linux/stat.h>
#include <sucompat.h>
#include <userd.h>
#include <uapi/linux/limits.h>
#include <sha256.h>
#include <baselib.h>
#include <ctype.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <log.h>
#include <common.h>

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
#define ANDROID_PACKAGES_LIST_PATH "/data/system/packages.list"
#define ANDROID_PACKAGES_LIST_TMP_PATH "/data/system/packages.list.tmp"

#define APK_SIG_BLOCK_MAGIC "APK Sig Block 42"
#define APK_SIG_BLOCK_MAGIC_LEN 16
#define APK_SIG_SCHEME_V2_BLOCK_ID 0x7109871au
#define APK_SIG_SCHEME_V3_BLOCK_ID 0xf05368c0u
#define APK_SIG_SCHEME_V31_BLOCK_ID 0x1b93ad61u
#define APK_CERT_MAX_LENGTH 4096

#define TRUSTED_MANAGER_DIGEST_LEN SHA256_BLOCK_SIZE
#define TRUSTED_MANAGER_UID_INVALID ((uid_t)-1)

struct trusted_manager_entry {
    const char package[64];
    const uint8_t digest[TRUSTED_MANAGER_DIGEST_LEN];
};

static const struct trusted_manager_entry trusted_managers[] = {
    {
        "me.bmax.apatch",
        {
            0xd7, 0x1d, 0xad, 0xc0, 0xca, 0x07, 0xbd, 0xf5,
            0x94, 0x38, 0x3b, 0xfb, 0x2a, 0x44, 0x51, 0x34,
            0xa0, 0x73, 0x39, 0xf1, 0x2a, 0x27, 0x04, 0x4a,
            0x1b, 0x32, 0x69, 0x81, 0xac, 0xf5, 0xf3, 0x19
        }
    },
    {
        "com.example.apatch",
        {
            0xe5, 0x11, 0x33, 0x12, 0x5f, 0xef, 0x56, 0xaa,
            0x52, 0x83, 0x91, 0xfc, 0xc2, 0x04, 0x94, 0xeb,
            0xb5, 0x38, 0xbd, 0x8e, 0x09, 0x3d, 0x6c, 0x47,
            0x5d, 0x6d, 0x00, 0x2a, 0x7a, 0x12, 0x1a, 0x8f
        }
    },
    { "", { 0 } }
};

static uid_t trusted_manager_uid = TRUSTED_MANAGER_UID_INVALID;
static int global_pkg_pos = 0;


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
    "    exec -- " SUPERCMD " su event boot-completed\n"
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
    data = vmalloc(*len + 1);
    if (!data) {
        filp_close(filp, 0);
        goto out;
    }
    loff_t pos = 0;
    kernel_read(filp, data, *len, &pos);
    ((char *)data)[*len] = '\0';
    filp_close(filp, 0);

out:
    set_priv_sel_allow(current, false);
    return data;
}

static int path_has_suffix(const char *path, const char *suffix)
{
    size_t path_len;
    size_t suffix_len;
    if (!path || !suffix) return 0;
    path_len = strlen(path);
    suffix_len = strlen(suffix);
    if (path_len < suffix_len) return 0;
    return strcmp(path + path_len - suffix_len, suffix) == 0;
}

static int is_packages_list_tmp_dentry_path(const char *path)
{
    return path_has_suffix(path, "/system/packages.list.tmp");
}

/* bounds-checked read: fails if [*pos, *pos+size) would fall outside [*pos, end) */
static int read_exact(struct file *fp, void *buf, size_t size, loff_t *pos, loff_t end)
{
    if (*pos < 0 || *pos > end || size > (size_t)(end - *pos)) return -EINVAL;
    return kernel_read(fp, buf, size, pos) == (ssize_t)size ? 0 : -EIO;
}

static int read_le32_bounded(struct file *fp, loff_t *pos, loff_t end, uint32_t *out)
{
    return read_exact(fp, out, sizeof(*out), pos, end);
}

static int read_le64_bounded(struct file *fp, loff_t *pos, loff_t end, uint64_t *out)
{
    return read_exact(fp, out, sizeof(*out), pos, end);
}

static int read_le16_bounded(struct file *fp, loff_t *pos, loff_t end, uint16_t *out)
{
    return read_exact(fp, out, sizeof(*out), pos, end);
}

/* reads a u32 length prefix at *pos and returns the end of the length-prefixed
 * field, bounded by container_end so a forged length can't escape its parent */
static int read_length_prefixed_end(struct file *fp, loff_t *pos, loff_t container_end, loff_t *value_end)
{
    uint32_t length;
    if (read_le32_bounded(fp, pos, container_end, &length)) return -EINVAL;
    if ((uint64_t)length > (uint64_t)(container_end - *pos)) return -EINVAL;
    *value_end = *pos + (loff_t)length;
    return 0;
}

static int cert_der_matches_trusted_digest(const uint8_t *cert_der, size_t cert_len, const uint8_t *expected_digest)
{
    uint8_t digest[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, cert_der, cert_len);
    sha256_final(&ctx, digest);



    return lib_memcmp(digest, expected_digest, TRUSTED_MANAGER_DIGEST_LEN) == 0 ? 0 : -EPERM;
}

static int apk_sig_block_matches_trusted_digest(struct file *fp, loff_t *pos, loff_t block_end,
                                                const uint8_t *expected_digest)
{
    loff_t signers_end, signer_end, signed_data_end, digests_end, certificates_end;
    uint32_t cert_len;
    uint8_t *cert_buf;

    // v2 block: signers sequence -> first signer -> signed data -> digests
    if (read_length_prefixed_end(fp, pos, block_end, &signers_end) ||
        read_length_prefixed_end(fp, pos, signers_end, &signer_end) ||
        read_length_prefixed_end(fp, pos, signer_end, &signed_data_end) ||
        read_length_prefixed_end(fp, pos, signed_data_end, &digests_end)) {
        return 0;
    }

    *pos = digests_end;
    if (read_length_prefixed_end(fp, pos, signed_data_end, &certificates_end) ||
        read_le32_bounded(fp, pos, certificates_end, &cert_len)) {
        return 0;
    }

    if (cert_len == 0 || cert_len > APK_CERT_MAX_LENGTH || (uint64_t)cert_len > (uint64_t)(certificates_end - *pos)) {
        log_boot("trusted manager apk cert length invalid: %u\n", cert_len);
        return 0;
    }

    cert_buf = vmalloc(cert_len);
    if (!cert_buf) {
        return 0;
    }

    if (read_exact(fp, cert_buf, cert_len, pos, certificates_end)) {
        kvfree(cert_buf);
        return 0;
    }

    if (!cert_der_matches_trusted_digest(cert_buf, cert_len, expected_digest)) {
        kvfree(cert_buf);
        return 2;
    }

    kvfree(cert_buf);
    return 1;
}

/* v1 (JAR) signing leaves META-INF/ RSA, DSA, or EC signature block entries
 * in the ZIP central directory; detect them without parsing the PKCS7 payload. */
static int apk_has_v1_signature(struct file *fp, loff_t cd_start, loff_t cd_end)
{
    loff_t pos = cd_start;

    while (pos < cd_end) {
        uint32_t sig;
        uint16_t name_len, extra_len, comment_len;
        char name[72];
        loff_t entry_start = pos;
        loff_t name_pos;

        if (read_le32_bounded(fp, &pos, cd_end, &sig) || sig != 0x02014b50u) {
            break;
        }

        pos = entry_start + 28;
        if (read_le16_bounded(fp, &pos, cd_end, &name_len) ||
            read_le16_bounded(fp, &pos, cd_end, &extra_len) ||
            read_le16_bounded(fp, &pos, cd_end, &comment_len)) {
            break;
        }
        if (entry_start + 46 + name_len + extra_len + comment_len > cd_end) {
            break;
        }

        if (name_len > 0 && name_len < sizeof(name)) {
            name_pos = entry_start + 46;
            if (!read_exact(fp, name, name_len, &name_pos, cd_end)) {
                name[name_len] = '\0';
                if (!strncmp(name, "META-INF/", 9) &&
                    (path_has_suffix(name, ".RSA") || path_has_suffix(name, ".DSA") || path_has_suffix(name, ".EC"))) {
                    return 1;
                }
            }
        }

        pos = entry_start + 46 + name_len + extra_len + comment_len;
    }
    return 0;
}

static int apk_matches_trusted_signature(const char *path, const uint8_t *expected_digest)
{
    int i;
    int rc = 0;
    int v2_blocks = 0;
    int v2_valid = 0;
    int v3_blocks = 0;
    int v3_valid = 0;
    int v31_blocks = 0;
    int v31_valid = 0;
    uint8_t magic[APK_SIG_BLOCK_MAGIC_LEN + 1] = { 0 };
    uint32_t cd_offset = 0;
    uint32_t cd_size = 0;
    uint32_t zip64_locator_magic;
    uint32_t eocd_sig;
    uint64_t size_of_block;
    uint64_t size_of_block_at_head;
    loff_t pos;
    loff_t file_size;
    loff_t eocd_offset = -1;
    loff_t pairs_end;
    struct file *fp;

    if (!path || !path[0]) return 0;

    set_priv_sel_allow(current, true);
    fp = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
    if (!fp || IS_ERR(fp)) {
        log_boot("trusted manager apk open failed: %s rc=%ld\n", path, PTR_ERR(fp));
        set_priv_sel_allow(current, false);
        return 0;
    }

    file_size = vfs_llseek(fp, 0, SEEK_END);
    if (file_size < 0) {
        goto out;
    }

    // https://en.wikipedia.org/wiki/Zip_(file_format)#End_of_central_directory_record_(EOCD)
    for (i = 0; i <= 0xffff; i++) {
        unsigned short n = 0;
        pos = file_size - i - 2;
        if (read_exact(fp, &n, sizeof(n), &pos, file_size)) {
            continue;
        }
        if (n == i) {
            pos -= 22;
            if (!read_le32_bounded(fp, &pos, file_size, &eocd_sig) && eocd_sig == 0x06054b50u) {
                eocd_offset = pos - sizeof(eocd_sig);
                break;
            }
        }
    }

    if (i > 0xffff || eocd_offset < 0) {
        goto out;
    }

    // ZIP64 keeps the real central-directory offset in a separate locator;
    // reject it so the (32-bit) offsets read below can't be spoofed
    if (eocd_offset >= 20) {
        pos = eocd_offset - 20;
        if (read_le32_bounded(fp, &pos, file_size, &zip64_locator_magic)) {
            goto out;
        }
        if (zip64_locator_magic == 0x07064b50u) {
            goto out;
        }
    }

    pos = eocd_offset + 12;
    if (read_le32_bounded(fp, &pos, file_size, &cd_size)) {
        goto out;
    }
    if (read_le32_bounded(fp, &pos, file_size, &cd_offset)) {
        goto out;
    }
    if ((uint64_t)cd_offset > (uint64_t)eocd_offset || (uint64_t)cd_size != (uint64_t)eocd_offset - cd_offset) {
        goto out;
    }
    if (cd_offset < 0x20) {
        goto out;
    }

    pairs_end = (loff_t)cd_offset - 0x18;
    pos = pairs_end;

    if (read_le64_bounded(fp, &pos, (loff_t)cd_offset, &size_of_block)) {
        goto out;
    }
    if (read_exact(fp, magic, APK_SIG_BLOCK_MAGIC_LEN, &pos, (loff_t)cd_offset)) {
        goto out;
    }
    if (strncmp((char *)magic, APK_SIG_BLOCK_MAGIC, APK_SIG_BLOCK_MAGIC_LEN) != 0) {
        goto out;
    }

    if (size_of_block < 0x18 || size_of_block > (uint64_t)cd_offset - 0x8) {
        goto out;
    }

    pos = (loff_t)cd_offset - (loff_t)size_of_block - 0x8;
    if (read_le64_bounded(fp, &pos, pairs_end, &size_of_block_at_head)) {
        goto out;
    }
    if (size_of_block_at_head != size_of_block) {
        goto out;
    }

    // scan every length-prefixed pair up to pairs_end; malformed lengths fail
    // the bounds check below instead of relying on an iteration cap
    while (pos < pairs_end) {
        uint32_t id;
        uint64_t size_of_pair;
        loff_t pair_end;

        if (read_le64_bounded(fp, &pos, pairs_end, &size_of_pair)) {
            goto out;
        }
        if (size_of_pair < sizeof(id) || size_of_pair > (uint64_t)(pairs_end - pos)) {
            goto out;
        }
        pair_end = pos + (loff_t)size_of_pair;
        if (read_le32_bounded(fp, &pos, pair_end, &id)) {
            goto out;
        }

        if (id == APK_SIG_SCHEME_V2_BLOCK_ID) {
            int match;
            v2_blocks++;
            match = apk_sig_block_matches_trusted_digest(fp, &pos, pair_end, expected_digest);
            if (match == 2) {
                v2_valid = 1;
            }
        } else if (id == APK_SIG_SCHEME_V3_BLOCK_ID) {
            int match;
            v3_blocks++;
            // v3's "signed data" starts with digests then certificates, same
            // layout as v2, so the same bounded parser applies here.
            match = apk_sig_block_matches_trusted_digest(fp, &pos, pair_end, expected_digest);
            if (match == 2) {
                v3_valid = 1;
            }
        } else if (id == APK_SIG_SCHEME_V31_BLOCK_ID) {
            int match;
            v31_blocks++;
            match = apk_sig_block_matches_trusted_digest(fp, &pos, pair_end, expected_digest);
            if (match == 2) {
                v31_valid = 1;
            }
        }

        pos = pair_end;
    }


    // only a lone, valid v2 signature is trusted; v1/v3/v3.1 verification
    // parsing above is kept for diagnostics but does not grant trust
    if (apk_has_v1_signature(fp, (loff_t)cd_offset, eocd_offset)) {
        log_boot("trusted manager apk unexpected v1 (JAR) signature scheme\n");
        goto out;
    }

    if (v3_blocks || v31_blocks) {
        log_boot("trusted manager apk unexpected v3/v3.1 signature scheme alongside v2\n");
        goto out;
    }

    if (!v2_valid) {
        log_boot("trusted manager apk sig invalid: v2=%d/%d v3=%d/%d v31=%d/%d\n",
                 v2_valid, v2_blocks, v3_valid, v3_blocks, v31_valid, v31_blocks);
        goto out;
    }

    rc = 1;

out:
    filp_close(fp, 0);
    set_priv_sel_allow(current, false);
    return rc;
}

static int lookup_package_list_uid(const char *package_name, uid_t *trusted_uid_out, int use_tmp)
{
    loff_t len = 0;
    const char *path = use_tmp ? ANDROID_PACKAGES_LIST_TMP_PATH : ANDROID_PACKAGES_LIST_PATH;
    char *content = (char *)kernel_read_file(path, &len);
    char *cursor;
    char *end;

    if (!trusted_uid_out) return -EINVAL;
    if (!content || len <= 0) {
        log_boot("trusted manager: failed to read %s\n", path);
        return -ENOENT;
    }

    cursor = content;
    end = content + len;
    while (cursor < end) {
        char *line = cursor;
        char *line_end = cursor;
        char *pkg;
        char *uid_str;
        unsigned long long uid_raw = 0;

        while (line_end < end && *line_end != '\n' && *line_end != '\r') {
            line_end++;
        }
        if (line_end < end) {
            *line_end = '\0';
            cursor = line_end + 1;
        } else {
            cursor = end;
        }

        while (*line && isspace(*line)) {
            line++;
        }
        if (!*line) {
            continue;
        }

        pkg = line;
        while (*line && !isspace(*line)) {
            line++;
        }
        if (!*line) {
            continue;
        }
        *line++ = '\0';

        while (*line && isspace(*line)) {
            line++;
        }
        if (!*line) {
            continue;
        }

        uid_str = line;
        while (*line && !isspace(*line)) {
            line++;
        }
        *line = '\0';

        if (strcmp(pkg, package_name) != 0) {
            continue;
        }
        if (kstrtoull(uid_str, 10, &uid_raw) || uid_raw > UINT_MAX) {
            kvfree(content);
            return -EINVAL;
        }

        *trusted_uid_out = (uid_t)uid_raw;
        kvfree(content);
        return 0;
    }

    kvfree(content);
    return -ENOENT;
}

/*
 * Kernel-space APK path discovery using iterate_dir.
 * Avoids shell/usermodehelper SELinux restrictions and packages.xml (binary
 * protobuf on Android 11+).
 *
 * Android 11+ layout: /data/app/~~<hash>/me.bmax.apatch-<hash>/base.apk
 * Pre-Android-11:     /data/app/me.bmax.apatch-<N>/base.apk
 *
 * We try both layouts: first a shallow scan of /data/app/ (pre-11), then a
 * two-level scan through the tilde-scramble directories (11+).
 */

/* Inner callback: scan one directory for a subdir starting with
 * TRUSTED_MANAGER_PACKAGE_TARGET "-".
 */
struct apk_inner_ctx {
    struct dir_context dctx; /* MUST be first member for safe cast */
    const char *outer_dir;   /* parent path, e.g. "/data/app/~~abc/" */
    char *result;
    size_t result_len;
    int found;
    const char *package;
};

struct apk_inner_ctx_int {
    struct dir_context_int dctx; /* MUST be first member for safe cast */
    const char *outer_dir;       /* parent path, e.g. "/data/app/~~abc/" */
    char *result;
    size_t result_len;
    int found;
    const char *package;
};

static bool apk_inner_actor(struct dir_context *dctx,
                            const char *name, int namelen,
                            loff_t offset, u64 ino, unsigned int d_type)
{
    struct apk_inner_ctx *ctx =
        container_of(dctx, struct apk_inner_ctx, dctx);

    const char *pkg;
    size_t len, outer_len, path_len;
    static const char base_apk[] = "/base.apk";

    if (!ctx || !ctx->result)
        return false;

    if (ctx->found)
        return false;

    pkg = ctx->package;


    if (!pkg || !pkg[0])
        return true;

    len = strnlen(pkg, 128);

    if ((size_t)namelen <= len)
        return true;

    if (memcmp(name, pkg, len) != 0)
        return true;

    if (name[len] != '-')
        return true;

    outer_len = strlen(ctx->outer_dir);
    path_len = outer_len + namelen + sizeof(base_apk);

    if (path_len >= ctx->result_len)
        return true;

    memcpy(ctx->result, ctx->outer_dir, outer_len);
    memcpy(ctx->result + outer_len, name, namelen);
    memcpy(ctx->result + outer_len + namelen,
           base_apk, sizeof(base_apk));

    ctx->found = 1;
    return false;
}

static int apk_inner_actor_int(struct dir_context_int *dctx,
                            const char *name, int namelen,
                            loff_t offset, u64 ino, unsigned int d_type)
{
    struct apk_inner_ctx_int *ctx =
        container_of(dctx, struct apk_inner_ctx_int, dctx);

    const char *pkg;
    size_t len, outer_len, path_len;
    static const char base_apk[] = "/base.apk";

    if (!ctx || !ctx->result)
        return 1;

    if (ctx->found)
        return 1;

    pkg = ctx->package;


    if (!pkg || !pkg[0])
        return 0;

    len = strnlen(pkg, 128);

    if ((size_t)namelen <= len)
        return 0;

    if (memcmp(name, pkg, len) != 0)
        return 0;

    if (name[len] != '-')
        return 0;

    outer_len = strlen(ctx->outer_dir);
    path_len = outer_len + namelen + sizeof(base_apk);

    if (path_len >= ctx->result_len)
        return 0;

    memcpy(ctx->result, ctx->outer_dir, outer_len);
    memcpy(ctx->result + outer_len, name, namelen);
    memcpy(ctx->result + outer_len + namelen,
           base_apk, sizeof(base_apk));

    ctx->found = 1;
    return 1;
}

/* Outer callback: scan /data/app/ for ~~* scramble directories, then descend */
struct apk_outer_ctx {
    struct dir_context dctx; /* MUST be first member */
    char *result;
    size_t result_len;
    int found;
    char *inner_path; /* heap-allocated: "/data/app/~~<hash>/" */
    size_t inner_path_len;
    const char *package;
};

struct apk_outer_ctx_int {
    struct dir_context_int dctx; /* MUST be first member */
    char *result;
    size_t result_len;
    int found;
    char *inner_path; /* heap-allocated: "/data/app/~~<hash>/" */
    size_t inner_path_len;
    const char *package;
};

static bool apk_outer_actor(struct dir_context *dctx,
                            const char *name, int namelen,
                            loff_t offset, u64 ino, unsigned int d_type)
{
    struct apk_outer_ctx *ctx = container_of(dctx, struct apk_outer_ctx, dctx);
    struct apk_inner_ctx *inner;
    struct file *inner_dir;
    int len;

    if (!ctx)
        return false;

    if (ctx->found)
        return false;

    if (namelen < 2 || name[0] != '~' || name[1] != '~')
        return true;

    len = snprintf(ctx->inner_path, ctx->inner_path_len,
                   "/data/app/%.*s/", namelen, name);
    if (len <= 0 || len >= (int)ctx->inner_path_len)
        return true;

    inner_dir = filp_open(ctx->inner_path, O_RDONLY | O_NOFOLLOW, 0);
    if (IS_ERR(inner_dir))
        return true;

    inner = vmalloc(sizeof(*inner));
    if (!inner) {
        filp_close(inner_dir, 0);
        return true;
    }
    memset(inner, 0, sizeof(*inner));

    inner->dctx.actor = apk_inner_actor;
    inner->dctx.pos = 0;
    inner->outer_dir = ctx->inner_path;
    inner->result = ctx->result;
    inner->result_len = ctx->result_len;
    inner->package = ctx->package;

    iterate_dir(inner_dir, &inner->dctx);
    filp_close(inner_dir, 0);

    if (inner->found) {
        ctx->found = 1;
        vfree(inner);
        return false;
    }

    vfree(inner);
    return true;
}
/* https://elixir.bootlin.com/linux/v6.0.19/source/include/linux/fs.h#L2049 */
/* Note: the return value semantics of the actor function changed in Linux 6.1:
 * true to continue iterating, false to stop -> 0 to continue, nonzero to stop.
 * We support both versions for compatibility with a wider range of kernels.
 */
static int apk_outer_actor_int(struct dir_context_int *dctx,
                            const char *name, int namelen,
                            loff_t offset, u64 ino, unsigned int d_type)
{
    struct apk_outer_ctx_int *ctx = container_of(dctx, struct apk_outer_ctx_int, dctx);
    struct apk_inner_ctx_int *inner;
    struct file *inner_dir;
    int len;

    if (!ctx)
        return 1;

    if (ctx->found)
        return 1;

    if (namelen < 2 || name[0] != '~' || name[1] != '~')
        return 0;

    len = snprintf(ctx->inner_path, ctx->inner_path_len,
                   "/data/app/%.*s/", namelen, name);
    if (len <= 0 || len >= (int)ctx->inner_path_len)
        return 0;

    inner_dir = filp_open(ctx->inner_path, O_RDONLY | O_NOFOLLOW, 0);
    if (IS_ERR(inner_dir))
        return 0;

    inner = vmalloc(sizeof(*inner));
    if (!inner) {
        filp_close(inner_dir, 0);
        return 0;
    }
    memset(inner, 0, sizeof(*inner));
    inner->dctx.actor = apk_inner_actor_int;
    inner->dctx.pos = 0;
    inner->outer_dir = ctx->inner_path;
    inner->result = ctx->result;
    inner->result_len = ctx->result_len;
    inner->package = ctx->package;

    iterate_dir_int(inner_dir, &inner->dctx);
    filp_close(inner_dir, 0);

    if (inner->found) {
        ctx->found = 1;
        vfree(inner);
        return 1;
    }

    vfree(inner);
    return 0;
}

static int find_trusted_manager_apk_path(char *apk_path,
                                         size_t apk_path_len,
                                         int index)
{
    
    log_boot("finding apk path for package: %s\n", trusted_managers[index].package);
    struct apk_outer_ctx *outer = NULL;
    struct apk_outer_ctx_int *outer_int = NULL;
    struct apk_inner_ctx *flat = NULL;
    struct apk_inner_ctx_int *flat_int = NULL;
    struct file *app_dir;
    int rc = -ENOENT;

    char *pkg_buf = NULL;

    if (!apk_path || apk_path_len == 0)
        return -EINVAL;

    if (index < 0)
        return -EINVAL;

    if (trusted_managers[index].package[0] == '\0')
        return -EINVAL;
    pkg_buf = vmalloc(64);
    if (!pkg_buf) return -ENOMEM;
    size_t len = strnlen(trusted_managers[index].package, 63);
    memcpy(pkg_buf, trusted_managers[index].package, len);
    pkg_buf[len] = '\0';
    apk_path[0] = '\0';

    if (kver >= VERSION(6, 1, 0)) {
        flat = vmalloc(sizeof(*flat));
        if (!flat) { rc = -ENOMEM; goto out_free; }

        outer = vmalloc(sizeof(*outer));
        if (!outer) { rc = -ENOMEM; goto out_free; }

        memset(flat, 0, sizeof(*flat));
        memset(outer, 0, sizeof(*outer));

        outer->inner_path = vmalloc(256);
        if (!outer->inner_path) { rc = -ENOMEM; goto out_free; }
        outer->inner_path_len = 256;
    } else {
        flat_int = vmalloc(sizeof(*flat_int));
        if (!flat_int) { rc = -ENOMEM; goto out_free; }

        outer_int = vmalloc(sizeof(*outer_int));
        if (!outer_int) { rc = -ENOMEM; goto out_free; }

        memset(flat_int, 0, sizeof(*flat_int));
        memset(outer_int, 0, sizeof(*outer_int));

        outer_int->inner_path = vmalloc(256);
        if (!outer_int->inner_path) { rc = -ENOMEM; goto out_free; }
        outer_int->inner_path_len = 256;
    }

    set_priv_sel_allow(current, true);

    app_dir = filp_open("/data/app/", O_RDONLY | O_NOFOLLOW, 0);

    if (IS_ERR(app_dir)) {
        log_boot("open /data/app failed rc=%ld\n", PTR_ERR(app_dir));
        set_priv_sel_allow(current, false);
        rc = -ENOENT;
        goto out_free;
    }

    /* ===== Pass1 ===== */
    if (kver >= VERSION(6, 1, 0)) {
        flat->dctx.actor = apk_inner_actor;
        flat->dctx.pos = 0;
        flat->outer_dir = "/data/app/";
        flat->result = apk_path;
        flat->result_len = apk_path_len;
        flat->package = pkg_buf;

        iterate_dir(app_dir, &flat->dctx);
    } else {
        flat_int->dctx.actor = apk_inner_actor_int;
        flat_int->dctx.pos = 0;
        flat_int->outer_dir = "/data/app/";
        flat_int->result = apk_path;
        flat_int->result_len = apk_path_len;
        flat_int->package = pkg_buf;

        iterate_dir_int(app_dir, &flat_int->dctx);
    }

    if ((flat && flat->found) || (flat_int && flat_int->found)) {
        log_boot("apk found (flat): %s\n", apk_path);
        rc = 0;
        goto out;
    }

    /* ===== Pass2 ===== */
    vfs_llseek(app_dir, 0, SEEK_SET);
    if (kver >= VERSION(6, 1, 0)) {
        outer->dctx.actor = apk_outer_actor;
        outer->dctx.pos = 0;
        outer->result = apk_path;
        outer->result_len = apk_path_len;
        outer->package = pkg_buf;

        iterate_dir(app_dir, &outer->dctx);
    } else {
        outer_int->dctx.actor = apk_outer_actor_int;
        outer_int->dctx.pos = 0;
        outer_int->result = apk_path;
        outer_int->result_len = apk_path_len;
        outer_int->package = pkg_buf;

        iterate_dir_int(app_dir, &outer_int->dctx);
    }

    if ((outer && outer->found) || (outer_int && outer_int->found)) {
        log_boot("apk found (scramble): %s\n", apk_path);
        rc = 0;
        goto out;
    }

    log_boot("apk not found: %s\n", pkg_buf);

out:
    filp_close(app_dir, 0);
    set_priv_sel_allow(current, false);
out_free:
    if (outer) {
        if (outer->inner_path) vfree(outer->inner_path);
        vfree(outer);
    }
    if (outer_int) {
        if (outer_int->inner_path) vfree(outer_int->inner_path);
        vfree(outer_int);
    }
    if (flat) vfree(flat);
    if (flat_int) vfree(flat_int);
    if (pkg_buf) vfree(pkg_buf);
    return rc;
}



static int refresh_trusted_manager_uid_from_packages_list(uid_t *trusted_uid_out, int use_tmp)
{
    uid_t last_uid = TRUSTED_MANAGER_UID_INVALID;
    int i, any_success = 0;
    
    char *apk_path; 

    if (!trusted_uid_out)
        return -EINVAL;

    apk_path = vmalloc(PATH_MAX);
    if (!apk_path) {
        log_boot("failed to allocate memory for apk_path\n");
        return -ENOMEM;
    }

    for (i = 0; trusted_managers[i].package[0] != '\0'; i++) {
        int rc;
        uid_t uid;

        rc = find_trusted_manager_apk_path(
                apk_path, PATH_MAX,
                i);
        if (rc) {
            log_boot("no apk via iterate for %s rc=%d, fallback to xml\n",
             trusted_managers[i].package, rc);


            continue;
        }

        if (!apk_matches_trusted_signature(
                apk_path, trusted_managers[i].digest)) {
            log_boot("apk signature invalid: %s\n", apk_path);
            continue;
        }


        rc = lookup_package_list_uid(
                trusted_managers[i].package,
                &uid,
                use_tmp);

        if (rc == 0) {
            last_uid = uid;
            any_success = 1;
            log_boot("uid ok pkg=%s uid=%u\n",
                     trusted_managers[i].package, uid);
        } else {
            log_boot("uid lookup fail pkg=%s rc=%d\n",
                     trusted_managers[i].package, rc);
        }
    }

    vfree(apk_path);

    if (!any_success) {
        log_boot("no valid trusted manager found\n");
        return -ENOENT;
    }

    *trusted_uid_out = last_uid;
    return 0;
}

int refresh_trusted_manager_uid(void)
{
    return refresh_trusted_manager_state();
}

static int refresh_trusted_manager_state_from_packages_list(int use_tmp)
{
    uid_t uid = TRUSTED_MANAGER_UID_INVALID;
    int rc = refresh_trusted_manager_uid_from_packages_list(&uid, use_tmp);
    if (rc) {
        log_boot("trusted manager refresh failed rc=%d\n", rc);
        return rc;
    }else{
        trusted_manager_uid = uid;
        log_boot("trusted manager refresh success uid=%u\n", uid);
    }

    
    
    return 0;
}

int refresh_trusted_manager_state(void)
{
    return refresh_trusted_manager_state_from_packages_list(0);
}
KP_EXPORT_SYMBOL(refresh_trusted_manager_uid);


int is_trusted_manager_uid_android(uid_t uid)
{
    uid_t trusted_uid = trusted_manager_uid;
    if (trusted_uid == TRUSTED_MANAGER_UID_INVALID) {
        return 0;
    }
    return uid == trusted_uid;
}
KP_EXPORT_SYMBOL(is_trusted_manager_uid_android);

uid_t get_trusted_manager_uid(void)
{
    return trusted_manager_uid;
}
KP_EXPORT_SYMBOL(get_trusted_manager_uid);

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
    extra_event_init(EXTRA_EVENT_PRE_EXEC_INIT);
}

static void post_user_exec_init()
{
    extra_event_init(EXTRA_EVENT_POST_EXEC_INIT);
}

static void pre_init_first_stage()
{
    extra_event_init(EXTRA_EVENT_PRE_FIRST_STAGE);
}

static void post_init_first_stage()
{
    extra_event_init(EXTRA_EVENT_POST_FIRST_STAGE);
}

static void pre_init_second_stage()
{
    extra_event_init(EXTRA_EVENT_PRE_SECOND_STAGE);
}

static void post_init_second_stage()
{
    extra_event_init(EXTRA_EVENT_POST_SECOND_STAGE);
}

static void on_first_app_process()
{
    /* The trusted-manager APK scan must NOT run here: it iterates /data/app and
     * verifies APK signatures, and doing it synchronously inside the first
     * app_process (zygote) execve stalls the framework on boot (regression from
     * "Change the trigger position").  The refresh is driven by the post-fs-data
     * "before" event in report_user_event() instead. */
}

static void handle_before_execve(hook_local_t *hook_local, char **__user u_filename_p, char **__user uargv,
                                 char **__user uenvp, void *udata)
{
    // unhook flag
    hook_local->data7 = 0;
    hook_local->data1 = 0;
    hook_local->data2 = 0;

    // Check if current process is trusted manager, set auto-su flag
    if (is_trusted_manager_uid(current_uid())) {
        hook_local->data0 = 1;
    } else {
        hook_local->data0 = 0;
    }

    if (current_uid() != 0 && !hook_local->data0) return;

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
            pre_init_first_stage();
            pre_user_exec_init();
            hook_local->data1 = 1;
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
                    hook_local->data2 = 1;
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
                        hook_local->data2 = 1;
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

static void handle_after_execve(hook_local_t *hook_local, long ret)
{
    // Auto-su for processes executed by trusted manager
    if (hook_local->data0 && ret >= 0) {
        commit_su(0, all_allow_sctx);
    }

    if (ret >= 0) {
        if (hook_local->data1) {
            post_user_exec_init();
            post_init_first_stage();
        }
        if (hook_local->data2) {
            post_init_second_stage();
        }
    }

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
    handle_after_execve(&args->local, args->ret);
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
    handle_after_execve(&args->local, args->ret);
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
    args->local.data3 = 0;
    static int replaced = 0;

    if (replaced) return;

    if (current_uid() != 0) return;

    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[256];
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

typedef char *(*kp_dentry_path_raw_t)(struct dentry *dentry, char *buf, int buflen);

static kp_dentry_path_raw_t kp_dentry_path_raw;

static void refresh_packages_list_tmp_rename(struct dentry *tmp_dentry)
{
    char path[128];
    char *buf;

    if (!tmp_dentry || !kp_dentry_path_raw) {
        return;
    }

    buf = kp_dentry_path_raw(tmp_dentry, path, sizeof(path));
    if (IS_ERR(buf)) {
        log_boot("packages.list rename: dentry_path_raw failed\n");
        return;
    }

    if (is_packages_list_tmp_dentry_path(buf)) {
        int rc;
        log_boot("packages.list rename matched: %s\n", buf);
        rc = refresh_trusted_manager_state_from_packages_list(1);
        log_boot("packages.list rename refresh trusted manager rc=%d\n", rc);
    }
}

static void after_security_path_rename(hook_fargs5_t *args, void *udata)
{
    if ((long)args->ret >= 0) {
        refresh_packages_list_tmp_rename((struct dentry *)args->arg1);
    }
}

static void after_security_inode_rename(hook_fargs5_t *args, void *udata)
{
    if ((long)args->ret >= 0) {
        refresh_packages_list_tmp_rename((struct dentry *)args->arg1);
    }
}

static void hook_rename_lsm(void)
{
    unsigned long addr;
    hook_err_t rc;

    kp_dentry_path_raw = (kp_dentry_path_raw_t)kallsyms_lookup_name("dentry_path_raw");
    if (!kp_dentry_path_raw) {
        log_boot("no symbol: dentry_path_raw\n");
        return;
    }

    addr = kallsyms_lookup_name("security_path_rename");
    if (addr) {
        rc = hook_wrap5((void *)addr, 0, after_security_path_rename, 0);
        log_boot("hook security_path_rename rc: %d\n", rc);
        return;
    }

    addr = kallsyms_lookup_name("security_inode_rename");
    if (addr) {
        rc = hook_wrap5((void *)addr, 0, after_security_inode_rename, 0);
        log_boot("hook security_inode_rename rc: %d\n", rc);
        return;
    }

    log_boot("no symbol: security_path_rename/security_inode_rename\n");
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

    hook_rename_lsm();

    unsigned long input_handle_event_addr = patch_config->input_handle_event;
    if (input_handle_event_addr) {
        rc = hook_wrap4((void *)input_handle_event_addr, before_input_handle_event, 0, 0);
        ret |= rc;
        log_boot("hook input_handle_event rc: %d\n", rc);
    }

    return ret;
}
