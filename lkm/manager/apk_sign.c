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

/* bounds-checked read: fails if [*pos, *pos+size) would fall outside [*pos, end) */
static int read_exact(struct file *fp, void *buf, size_t size, loff_t *pos, loff_t end)
{
	if (*pos < 0 || *pos > end || size > (size_t)(end - *pos))
		return -EINVAL;
	return kernel_read(fp, buf, size, pos) == (ssize_t)size ? 0 : -EIO;
}

static int read_le32_bounded(struct file *fp, loff_t *pos, loff_t end, u32 *out)
{
	return read_exact(fp, out, sizeof(*out), pos, end);
}

static int read_le64_bounded(struct file *fp, loff_t *pos, loff_t end, u64 *out)
{
	return read_exact(fp, out, sizeof(*out), pos, end);
}

static int read_le16_bounded(struct file *fp, loff_t *pos, loff_t end, u16 *out)
{
	return read_exact(fp, out, sizeof(*out), pos, end);
}

/* reads a u32 length prefix at *pos and returns the end of the length-prefixed
 * field, bounded by container_end so a forged length can't escape its parent */
static int read_length_prefixed_end(struct file *fp, loff_t *pos, loff_t container_end, loff_t *value_end)
{
	u32 length;
	if (read_le32_bounded(fp, pos, container_end, &length))
		return -EINVAL;
	if ((u64)length > (u64)(container_end - *pos))
		return -EINVAL;
	*value_end = *pos + (loff_t)length;
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

/* Parse one v2 signer block; returns 1 if the cert matches, 0 otherwise. */
static int sig_block_matches_digest(struct file *fp, loff_t *pos, loff_t block_end, const u8 *expected)
{
	loff_t signers_end, signer_end, signed_data_end, digests_end, certificates_end;
	u32 cert_len;
	u8 *cert_buf;

	/* v2 block: signers sequence -> first signer -> signed data -> digests */
	if (read_length_prefixed_end(fp, pos, block_end, &signers_end) ||
	    read_length_prefixed_end(fp, pos, signers_end, &signer_end) ||
	    read_length_prefixed_end(fp, pos, signer_end, &signed_data_end) ||
	    read_length_prefixed_end(fp, pos, signed_data_end, &digests_end))
		return 0;

	*pos = digests_end;
	if (read_length_prefixed_end(fp, pos, signed_data_end, &certificates_end) ||
	    read_le32_bounded(fp, pos, certificates_end, &cert_len))
		return 0;

	if (cert_len == 0 || cert_len > APK_CERT_MAX_LENGTH || (u64)cert_len > (u64)(certificates_end - *pos)) {
		logkd("apk cert length invalid: %u\n", cert_len);
		return 0;
	}

	cert_buf = vmalloc(cert_len);
	if (!cert_buf)
		return 0;
	if (read_exact(fp, cert_buf, cert_len, pos, certificates_end)) {
		vfree(cert_buf);
		return 0;
	}
	if (cert_der_matches_trusted_digest(cert_buf, cert_len, expected)) {
		vfree(cert_buf);
		return 0;
	}
	vfree(cert_buf);
	return 1;
}

static int name_has_suffix(const char *name, size_t name_len, const char *suffix)
{
	size_t suffix_len = strlen(suffix);
	if (name_len < suffix_len)
		return 0;
	return !memcmp(name + name_len - suffix_len, suffix, suffix_len);
}

/* v1 (JAR) signing leaves META-INF/ RSA, DSA, or EC signature block entries
 * in the ZIP central directory; detect them without parsing the PKCS7 payload. */
static int apk_has_v1_signature(struct file *fp, loff_t cd_start, loff_t cd_end)
{
	loff_t pos = cd_start;

	while (pos < cd_end) {
		u32 sig;
		u16 name_len, extra_len, comment_len;
		char name[72];
		loff_t entry_start = pos;
		loff_t name_pos;

		if (read_le32_bounded(fp, &pos, cd_end, &sig) || sig != 0x02014b50u)
			break;

		pos = entry_start + 28;
		if (read_le16_bounded(fp, &pos, cd_end, &name_len) ||
		    read_le16_bounded(fp, &pos, cd_end, &extra_len) ||
		    read_le16_bounded(fp, &pos, cd_end, &comment_len))
			break;
		if (entry_start + 46 + name_len + extra_len + comment_len > cd_end)
			break;

		if (name_len > 0 && name_len < sizeof(name)) {
			name_pos = entry_start + 46;
			if (!read_exact(fp, name, name_len, &name_pos, cd_end)) {
				if (name_len > 9 && !memcmp(name, "META-INF/", 9) &&
				    (name_has_suffix(name, name_len, ".RSA") ||
				     name_has_suffix(name, name_len, ".DSA") ||
				     name_has_suffix(name, name_len, ".EC")))
					return 1;
			}
		}

		pos = entry_start + 46 + name_len + extra_len + comment_len;
	}
	return 0;
}

static int apk_matches_digest(const char *path, const u8 *expected)
{
	int i, rc = 0;
	int v2_blocks = 0, v2_valid = 0;
	int v3_blocks = 0, v3_valid = 0;
	int v31_blocks = 0, v31_valid = 0;
	u8 magic[APK_SIG_BLOCK_MAGIC_LEN + 1] = { 0 };
	u32 cd_offset = 0, cd_size = 0, zip64_locator_magic, eocd_sig;
	u64 size_of_block, size_of_block_at_head;
	loff_t pos, file_size, eocd_offset = -1, pairs_end;
	struct file *fp;

	if (!path || !path[0])
		return 0;

	fp = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
	if (IS_ERR(fp)) {
		logkd("apk open failed %s: %ld\n", path, PTR_ERR(fp));
		return 0;
	}

	file_size = vfs_llseek(fp, 0, SEEK_END);
	if (file_size < 0)
		goto out;

	/* locate the EOCD (end of central directory) by scanning the tail. */
	for (i = 0; i <= 0xffff; i++) {
		u16 n = 0;
		pos = file_size - i - 2;
		if (read_exact(fp, &n, sizeof(n), &pos, file_size))
			continue;
		if (n == i) {
			pos -= 22;
			if (!read_le32_bounded(fp, &pos, file_size, &eocd_sig) && eocd_sig == 0x06054b50u) {
				eocd_offset = pos - sizeof(eocd_sig);
				break;
			}
		}
	}
	if (i > 0xffff || eocd_offset < 0)
		goto out;

	/* ZIP64 keeps the real central-directory offset in a separate locator;
	 * reject it so the (32-bit) offsets read below can't be spoofed. */
	if (eocd_offset >= 20) {
		pos = eocd_offset - 20;
		if (read_le32_bounded(fp, &pos, file_size, &zip64_locator_magic))
			goto out;
		if (zip64_locator_magic == 0x07064b50u)
			goto out;
	}

	pos = eocd_offset + 12;
	if (read_le32_bounded(fp, &pos, file_size, &cd_size))
		goto out;
	if (read_le32_bounded(fp, &pos, file_size, &cd_offset))
		goto out;
	if ((u64)cd_offset > (u64)eocd_offset || (u64)cd_size != (u64)eocd_offset - cd_offset)
		goto out;
	if (cd_offset < 0x20)
		goto out;

	pairs_end = (loff_t)cd_offset - 0x18;
	pos = pairs_end;

	if (read_le64_bounded(fp, &pos, (loff_t)cd_offset, &size_of_block))
		goto out;
	if (read_exact(fp, magic, APK_SIG_BLOCK_MAGIC_LEN, &pos, (loff_t)cd_offset))
		goto out;
	if (strncmp((char *)magic, APK_SIG_BLOCK_MAGIC, APK_SIG_BLOCK_MAGIC_LEN) != 0)
		goto out;

	if (size_of_block < 0x18 || size_of_block > (u64)cd_offset - 0x8)
		goto out;

	pos = (loff_t)cd_offset - (loff_t)size_of_block - 0x8;
	if (read_le64_bounded(fp, &pos, pairs_end, &size_of_block_at_head))
		goto out;
	if (size_of_block_at_head != size_of_block)
		goto out;

	/* scan every length-prefixed pair up to pairs_end; malformed lengths fail
	 * the bounds check below instead of relying on an iteration cap. */
	while (pos < pairs_end) {
		u32 id;
		u64 size_of_pair;
		loff_t pair_end;

		if (read_le64_bounded(fp, &pos, pairs_end, &size_of_pair))
			goto out;
		if (size_of_pair < sizeof(id) || size_of_pair > (u64)(pairs_end - pos))
			goto out;
		pair_end = pos + (loff_t)size_of_pair;
		if (read_le32_bounded(fp, &pos, pair_end, &id))
			goto out;

		if (id == APK_SIG_SCHEME_V2_BLOCK_ID) {
			v2_blocks++;
			if (sig_block_matches_digest(fp, &pos, pair_end, expected) == 1)
				v2_valid = 1;
		} else if (id == APK_SIG_SCHEME_V3_BLOCK_ID) {
			/* v3's "signed data" starts with digests then certificates,
			 * same layout as v2, so the same bounded parser applies. */
			v3_blocks++;
			if (sig_block_matches_digest(fp, &pos, pair_end, expected) == 1)
				v3_valid = 1;
		} else if (id == APK_SIG_SCHEME_V31_BLOCK_ID) {
			v31_blocks++;
			if (sig_block_matches_digest(fp, &pos, pair_end, expected) == 1)
				v31_valid = 1;
		}

		pos = pair_end;
	}

	/* only a lone, valid v2 signature is trusted; v1/v3/v3.1 verification
	 * parsing above is kept for diagnostics but does not grant trust */
	if (apk_has_v1_signature(fp, (loff_t)cd_offset, eocd_offset)) {
		logkd("apk unexpected v1 (JAR) signature scheme\n");
		goto out;
	}

	if (v3_blocks || v31_blocks) {
		logkd("apk unexpected v3/v3.1 signature scheme alongside v2\n");
		goto out;
	}

	if (!v2_valid) {
		logkd("apk sig invalid: v2=%d/%d v3=%d/%d v31=%d/%d\n",
		      v2_valid, v2_blocks, v3_valid, v3_blocks, v31_valid, v31_blocks);
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
