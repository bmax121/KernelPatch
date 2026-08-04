// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * APK v2/v3 signing-block certificate verification, ported from
 * kernel/patch/android/userd.c and adapted to kernel VFS APIs. The cert bytes
 * are SHA256'd and compared to the trusted APatch digests.
 */
#include "apk_sign.h"

#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "../include/kp_lkm.h"
#include "../include/sha256.h"

#define APK_SIG_BLOCK_MAGIC "APK Sig Block 42"
#define APK_SIG_BLOCK_MAGIC_LEN 16
#define APK_SIG_SCHEME_V2_BLOCK_ID 0x7109871au
#define APK_SIG_SCHEME_V3_BLOCK_ID 0xf05368c0u
#define APK_SIG_SCHEME_V31_BLOCK_ID 0x1b93ad61u
#define APK_CERT_MAX_LENGTH 4096

const struct kp_trusted_manager kp_trusted_managers[] = {
	{
		.package = "me.bmax.apatch",
		.digest = {
			0xd7, 0x1d, 0xad, 0xc0, 0xca, 0x07, 0xbd, 0xf5,
			0x94, 0x38, 0x3b, 0xfb, 0x2a, 0x44, 0x51, 0x34,
			0xa0, 0x73, 0x39, 0xf1, 0x2a, 0x27, 0x04, 0x4a,
			0x1b, 0x32, 0x69, 0x81, 0xac, 0xf5, 0xf3, 0x19,
		},
	},
	{
		.package = "com.example.apatch",
		.digest = {
			0xe5, 0x11, 0x33, 0x12, 0x5f, 0xef, 0x56, 0xaa,
			0x52, 0x83, 0x91, 0xfc, 0xc2, 0x04, 0x94, 0xeb,
			0xb5, 0x38, 0xbd, 0x8e, 0x09, 0x3d, 0x6c, 0x47,
			0x5d, 0x6d, 0x00, 0x2a, 0x7a, 0x12, 0x1a, 0x8f,
		},
	},
	{ .package = NULL, .digest = { 0 } },
};

int kp_trusted_manager_count(void)
{
	int n = 0;
	while (kp_trusted_managers[n].package)
		n++;
	return n;
}

static int read_le32(struct file *fp, loff_t *pos, u32 *out)
{
	return kernel_read(fp, out, sizeof(*out), pos) == sizeof(*out) ? 0 : -EIO;
}

static int read_le64(struct file *fp, loff_t *pos, u64 *out)
{
	return kernel_read(fp, out, sizeof(*out), pos) == sizeof(*out) ? 0 : -EIO;
}

static int skip_bytes(loff_t *pos, u64 len)
{
	*pos += (loff_t)len;
	return 0;
}

/* SHA256 the DER cert and compare against the trusted digest. */
static int cert_der_matches_trusted_digest(const u8 *cert_der, size_t cert_len, const u8 *expected)
{
	u8 digest[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, cert_der, cert_len);
	sha256_final(&ctx, digest);
	return !memcmp(digest, expected, 32) ? 0 : -EPERM;
}

/* Parse one v2/v3 signer block; returns 1 if cert matches, 2 (=v2_valid) on
 * match like KP, 0 otherwise. Mirrors KP's apk_sig_block_matches_trusted_digest. */
static int sig_block_matches_digest(struct file *fp, u32 *size4, loff_t *pos, u32 *offset, const u8 *expected)
{
	u8 *cert_buf;

	if (read_le32(fp, pos, size4)) return 0; /* signer-sequence length */
	if (read_le32(fp, pos, size4)) return 0; /* signer length */
	if (read_le32(fp, pos, size4)) return 0; /* signed data length */
	*offset += sizeof(*size4) * 3;

	if (read_le32(fp, pos, size4)) return 0; /* digests-sequence length */
	if (skip_bytes(pos, *size4)) return 0;
	*offset += sizeof(*size4) + *size4;

	if (read_le32(fp, pos, size4)) return 0; /* certificates length */
	if (read_le32(fp, pos, size4)) return 0; /* certificate length */
	*offset += sizeof(*size4) * 2;

	if (*size4 == 0 || *size4 > APK_CERT_MAX_LENGTH) {
		logkd("apk cert length invalid: %u\n", *size4);
		return 0;
	}
	*offset += *size4;

	cert_buf = vmalloc(*size4);
	if (!cert_buf)
		return 0;
	if (kernel_read(fp, cert_buf, *size4, pos) != *size4) {
		vfree(cert_buf);
		return 0;
	}
	if (cert_der_matches_trusted_digest(cert_buf, *size4, expected)) {
		vfree(cert_buf);
		return 0;
	}
	vfree(cert_buf);
	return 1;
}

static int apk_matches_digest(const char *path, const u8 *expected)
{
	int i, rc = 0;
	int v2_blocks = 0, v2_valid = 0, v3_present = 0, v31_present = 0;
	u8 magic[APK_SIG_BLOCK_MAGIC_LEN + 1] = { 0 };
	u32 size4, offset;
	u64 size8, size_of_block;
	loff_t pos;
	struct file *fp;

	if (!path || !path[0])
		return 0;

	fp = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
	if (IS_ERR(fp)) {
		logkd("apk open failed %s: %ld\n", path, PTR_ERR(fp));
		return 0;
	}

	/* locate the EOCD (end of central directory) by scanning the tail. */
	for (i = 0; i <= 0xffff; i++) {
		u16 n = 0;
		pos = vfs_llseek(fp, -i - 2, SEEK_END);
		if (pos < 0)
			continue;
		if (kernel_read(fp, &n, sizeof(n), &pos) != sizeof(n))
			continue;
		if (n == i) {
			pos -= 22;
			if (!read_le32(fp, &pos, &size4) && size4 == 0x06054b50u)
				break;
		}
	}
	if (i > 0xffff)
		goto out;

	pos += 12;
	if (read_le32(fp, &pos, &size4))
		goto out;
	pos = (loff_t)size4 - 0x18;

	if (read_le64(fp, &pos, &size8))
		goto out;
	if (kernel_read(fp, magic, APK_SIG_BLOCK_MAGIC_LEN, &pos) != APK_SIG_BLOCK_MAGIC_LEN)
		goto out;
	if (strncmp((char *)magic, APK_SIG_BLOCK_MAGIC, APK_SIG_BLOCK_MAGIC_LEN) != 0)
		goto out;

	pos = (loff_t)size4 - (loff_t)(size8 + 0x8);
	if (read_le64(fp, &pos, &size_of_block))
		goto out;
	if (size_of_block != size8)
		goto out;

	for (i = 0; i < 16; i++) {
		u32 id;
		offset = sizeof(id);
		if (read_le64(fp, &pos, &size8))
			goto out;
		if (size8 == size_of_block)
			break;
		if (read_le32(fp, &pos, &id))
			goto out;

		if (id == APK_SIG_SCHEME_V2_BLOCK_ID) {
			v2_blocks++;
			if (sig_block_matches_digest(fp, &size4, &pos, &offset, expected) == 1)
				v2_valid = 1;
		} else if (id == APK_SIG_SCHEME_V3_BLOCK_ID) {
			v3_present = 1;
		} else if (id == APK_SIG_SCHEME_V31_BLOCK_ID) {
			v31_present = 1;
		}

		if (size8 < offset)
			goto out;
		if (skip_bytes(&pos, size8 - offset))
			goto out;
	}

	if (!v2_valid) {
		logkd("apk sig invalid: v2_blocks=%d v2_valid=%d v3=%d v31=%d\n",
		      v2_blocks, v2_valid, v3_present, v31_present);
		goto out;
	}
	rc = 1;

out:
	filp_close(fp, NULL);
	return rc;
}

int kp_manager_apk_match(const char *path)
{
	int i;
	for (i = 0; kp_trusted_managers[i].package; i++) {
		if (apk_matches_digest(path, kp_trusted_managers[i].digest)) {
			logki("trusted manager apk matched: %s (pkg %s)\n", path,
			      kp_trusted_managers[i].package);
			return i;
		}
	}
	return -1;
}
