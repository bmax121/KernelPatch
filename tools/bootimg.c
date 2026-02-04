// we need  zlib-devel liblz4-devel liblzma-devel
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>

#include "bootimg.h"
#include "common.h"
#include "lib/lz4/lz4.h"
#include "lib/lz4/lz4frame.h"
#include "lib/bz2/bzlib.h"
#include "lib/xz/xz.h"

// #include "lib/zstd/zstd.h"



static uint32_t fdt32_to_cpu(uint32_t val) {
    return ((val << 24) & 0xff000000) |
           ((val << 8)  & 0x00ff0000) |
           ((val >> 8)  & 0x0000ff00) |
           ((val >> 24) & 0x000000ff);
}

static void *my_memmem(const void *haystack, size_t haystacklen,
                       const void *needle, size_t needlelen) {
    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;

    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;
    size_t i;

    for (i = 0; i <= haystacklen - needlelen; i++) {
        if (h[i] == n[0] && memcmp(&h[i], n, needlelen) == 0) {
            return (void *)&h[i];
        }
    }
    return NULL;
}

static int find_dtb_offset(const uint8_t *buf, unsigned int sz) {
    if (!buf || sz < sizeof(struct fdt_header)) return -1;
    const uint8_t *curr = buf;
    const uint8_t *end = buf + sz;

    while (curr < end - sizeof(struct fdt_header)) {
        curr = my_memmem(curr, end - curr, DTB_MAGIC, 4);
        if (curr == NULL) return -1;

        struct fdt_header *fdt_hdr = (struct fdt_header *)curr;
        uint32_t totalsize = fdt32_to_cpu(fdt_hdr->totalsize);
        uint32_t off_dt_struct = fdt32_to_cpu(fdt_hdr->off_dt_struct);
        if (totalsize > (uint32_t)(end - curr) || totalsize <= 0x48) {
            curr += 4;
            continue;
        }

        //  FDT_BEGIN_NODE (0x00000001)
        if (curr + off_dt_struct + 4 <= end) {
            uint32_t *tag = (uint32_t *)(curr + off_dt_struct);
            if (fdt32_to_cpu(*tag) == 0x00000001) {
                return (int)(curr - buf);
            }
        }
        curr += 4;
    }
    return -1;
}

int write_data_to_file(const char *path, const void *data, size_t size) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    fwrite(data, 1, size, fp);
    fclose(fp);
    return 0;
}

int compress_gzip(const uint8_t *in_data, size_t in_size, uint8_t **out_data, uint32_t *out_size) {
    z_stream strm = {0};
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) 
        return -1;

    uint32_t max_out_size = deflateBound(&strm, in_size);
    *out_data = malloc(max_out_size);
    if (!*out_data) { deflateEnd(&strm); return -1; }

    strm.next_in = (Bytef *)in_data;
    strm.avail_in = in_size;
    strm.next_out = *out_data;
    strm.avail_out = max_out_size;

    int ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        free(*out_data);
        deflateEnd(&strm);
        return -2;
    }

    *out_size = strm.total_out;
    deflateEnd(&strm);
    return 0;
}
int decompress_gzip(const uint8_t *in_data, size_t in_size, const char *out_path) {
    z_stream strm = {0};
    strm.next_in = (Bytef *)in_data;
    strm.avail_in = in_size;

    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) return -1;

    FILE *out = fopen(out_path, "wb");
    if (!out) { inflateEnd(&strm); return -1; }

    uint8_t out_buf[40960]; // 40KB buffer
    int ret;
    do {
        strm.next_out = out_buf;
        strm.avail_out = sizeof(out_buf);
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret < 0 && ret != Z_STREAM_END) {
            tools_logi("Error: Gzip inflate failed (err: %d)\n", ret);
            fclose(out);
            inflateEnd(&strm);
            return -2;
        }
        size_t have = sizeof(out_buf) - strm.avail_out;
        fwrite(out_buf, 1, have, out);
    } while (ret != Z_STREAM_END);

    fclose(out);
    inflateEnd(&strm);
    return 0;
}

int compress_lz4(const uint8_t *in_data, size_t in_size, uint8_t **out_data, uint32_t *out_size) {

    size_t max_out_size = LZ4F_compressFrameBound(in_size, NULL);
    
    *out_data = (uint8_t *)malloc(max_out_size);
    if (!*out_data) {
        return -1;
    }

    // 2. use default config (NULL -> default LZ4F_preferences_t)
    // LZ4F_compressFrame will produce a standard LZ4 frame (magic number 0x184D2204)
    size_t compressed_size = LZ4F_compressFrame(*out_data, max_out_size, in_data, in_size, NULL);

    if (LZ4F_isError(compressed_size)) {
        free(*out_data);
        return -2;
    }

    *out_size = (uint32_t)compressed_size;
    return 0;
}
int compress_lz4_le(const uint8_t *in_data, size_t in_size, uint8_t **out_data, uint32_t *out_size) {
    int max_block_size = LZ4_compressBound((int)in_size);

    uint32_t total_max_size = 4 + max_block_size;
    *out_data = (uint8_t *)malloc(total_max_size);
    if (!*out_data) {
        return -1;
    }

    (*out_data)[0] = 0x02;
    (*out_data)[1] = 0x21;
    (*out_data)[2] = 0x4C;
    (*out_data)[3] = 0x18;

    int compressed_bytes = LZ4_compress_default(
        (const char*)in_data, 
        (char*)(*out_data + 4), 
        (int)in_size, 
        max_block_size
    );
    if (compressed_bytes <= 0) {
        free(*out_data);
        *out_data = NULL;
        return -2;
    }
    *out_size = 4 + (uint32_t)compressed_bytes;
    return 0; 
}

// int compress_zstd(const uint8_t *in_data, size_t in_size, uint8_t **out_data, uint32_t *out_size) {
//     size_t const max_out_size = ZSTD_compressBound(in_size);
//     *out_data = malloc(max_out_size);
//     if (!*out_data) return -1;
//     size_t const cSize = ZSTD_compress(*out_data, max_out_size, in_data, in_size, 3);

//     if (ZSTD_isError(cSize)) {
//         free(*out_data);
//         return -2;
//     }
//     *out_size = (uint32_t)cSize;
//     return 0;
// }
// int decompress_zstd(const uint8_t *src, size_t srcSize, uint8_t **dst, uint32_t *dstSize) {
//     unsigned long long const rSize = ZSTD_getFrameContentSize(src, srcSize);
//     if (rSize == ZSTD_CONTENTSIZE_ERROR) return -1;
//     if (rSize == ZSTD_CONTENTSIZE_UNKNOWN) return -2;

//     *dst = malloc((size_t)rSize);
//     if (!*dst) return -3;

//     size_t const dSize = ZSTD_decompress(*dst, (size_t)rSize, src, srcSize);

//     if (ZSTD_isError(dSize)) {
//         free(*dst);
//         return -4;
//     }
//     *dstSize = (uint32_t)dSize;
//     return 0;
// }

int decompress_xz(const uint8_t *src, size_t srcSize, uint8_t **dst, uint32_t *dstSize) {

    xz_crc32_init();


    struct xz_dec *s = xz_dec_init(XZ_SINGLE, 0);
    if (s == NULL) return -1;


    uint32_t dstCapacity = 128 * 1024 * 1024;
    *dst = (uint8_t *)malloc(dstCapacity);
    if (!*dst) {
        xz_dec_end(s);
        return -1;
    }

    struct xz_buf b;
    b.in = src;
    b.in_pos = 0;
    b.in_size = srcSize;
    b.out = *dst;
    b.out_pos = 0;
    b.out_size = dstCapacity;
    enum xz_ret ret = xz_dec_run(s, &b);

    if (ret != XZ_STREAM_END) {
        tools_loge("XZ Decompression failed: %d\n", ret);
        free(*dst);
        xz_dec_end(s);
        return -1;
    }

    *dstSize = (uint32_t)b.out_pos;
    xz_dec_end(s);
    return 0;
}

int decompress_lzma(const uint8_t *src, size_t srcSize, uint8_t **dst, uint32_t *dstSize) {
    xz_crc32_init();

    struct xz_dec *s = xz_dec_init(XZ_SINGLE, 0);
    if (!s) return -1;

    uint32_t dstCapacity = 128 * 1024 * 1024; 
    *dst = (uint8_t *)malloc(dstCapacity);
    if (!*dst) {
        xz_dec_end(s);
        return -1;
    }

    struct xz_buf b;
    b.in = src;
    b.in_pos = 0;
    b.in_size = srcSize;
    b.out = *dst;
    b.out_pos = 0;
    b.out_size = dstCapacity;

    enum xz_ret ret = xz_dec_run(s, &b);

    if (ret != XZ_STREAM_END) {
        tools_loge("Your xz-embedded version only supports XZ container (Method 6).\n");
        free(*dst);
        xz_dec_end(s);
        return -1;
    }

    *dstSize = (uint32_t)b.out_pos;
    xz_dec_end(s);
    return 0;
}

int auto_depress(const uint8_t *data, size_t size, const char *out_path) {
    if (size < 4) return -1;
    compress_head k_head;
    memcpy(&k_head, data, sizeof(k_head));
    int method = detect_compress_method(k_head);

    
    if (method == 1) { //Gzip
        tools_logi("Detected GZIP compressed kernel.\n");
        if (decompress_gzip(data, size, out_path) == 0) {
            tools_logi(" Decompressed to %s\n", out_path);
            return 0;
        } else {
            tools_logi(" Gzip decompression failed.\n");
            return -1;
        }
    }
    
 
    if (method == 2) { 
        tools_logi(" Detected LZ4 Frame. Decompressing with lz4frame...\n");
        LZ4F_decompressionContext_t dctx;
        LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);

        size_t dstCapacity = 64 * 1024 * 1024;
        void* dst = malloc(dstCapacity);
        if (!dst) return -1;

        size_t consumedSize = size;
        size_t producedSize = dstCapacity;

        size_t ret = LZ4F_decompress(dctx, dst, &producedSize, data, &consumedSize, NULL);

        if (LZ4F_isError(ret)) {
            tools_loge("LZ4 Decompression failed: %s\n", LZ4F_getErrorName(ret));
            free(dst);
            LZ4F_freeDecompressionContext(dctx);
            return -1;
        } else {
            tools_logi("Decompressed: %zu bytes\n", producedSize);
            write_data_to_file(out_path, (uint8_t*)dst, (uint32_t)producedSize);
            free(dst);
            LZ4F_freeDecompressionContext(dctx);
            return 0;
        }
    }

    if (method == 3) { 
        tools_logi("Detected LZ4 Legacy. Decompressing with LZ4 Block API...\n");

        const char* compressed_ptr = (const char*)data + 4;
        int compressed_size = (int)size - 4;

        size_t dstCapacity = 64 * 1024 * 1024;
        void* dst = malloc(dstCapacity);
        if (!dst) return -1;

        int ret = LZ4_decompress_safe(compressed_ptr, (char*)dst, compressed_size, (int)dstCapacity);

        if (ret < 0) {
            tools_loge("LZ4 Legacy decompression failed.\n");
            free(dst);
            return -1;
        } else {
            tools_logi("Decompressed: %d bytes\n", ret);
            write_data_to_file(out_path, (uint8_t*)dst, (uint32_t)ret);
            free(dst);
            return 0;
        }
    }

    // till now no kernel use this
    // if (method == 4) { 
    //     tools_logi("Detected ZSTD compressed kernel. Decompressing...\n");
    //     unsigned long long const rSize = ZSTD_getFrameContentSize(data, size);
    //     if (rSize == ZSTD_CONTENTSIZE_ERROR || rSize == ZSTD_CONTENTSIZE_UNKNOWN) {
    //         tools_loge("Not a valid Zstd frame or size unknown.\n");
    //         return -1;
    //     }

    //     uint8_t *dst = malloc((size_t)rSize);
    //     if (!dst) return -1;

    //     size_t const dSize = ZSTD_decompress(dst, (size_t)rSize, data, size);

    //     if (ZSTD_isError(dSize)) {
    //         tools_loge(" Zstd Decompression failed: %s\n", ZSTD_getErrorName(dSize));
    //         free(dst);
    //         return -1;
    //     } else {
    //         tools_logi(" Decompressed: %zu bytes\n", dSize);
    //         write_data_to_file(out_path, dst, (uint32_t)dSize);
    //         free(dst);
    //         return 0;
    //     }
    // }

    if (method == 5) { // BZIP2
        tools_logi("Detected BZIP2. Decompressing...\n");


        unsigned int dstCapacity = 64 * 1024 * 1024; 
        void* dst = malloc(dstCapacity);
        if (!dst) {
            tools_loge("Failed to allocate memory for BZIP2 decompression.\n");
            return -1;
        }

        unsigned int producedSize = dstCapacity;
        unsigned int consumedSize = (unsigned int)size;

        int ret = BZ2_bzBuffToBuffDecompress((char*)dst, &producedSize, (char*)data, consumedSize, 0, 0);

        if (ret != BZ_OK) {
            tools_loge(" BZIP2 Decompression failed with error code: %d\n", ret);
            free(dst);
            return -1;
        }

        tools_logi(" BZIP2 Decompressed: %u bytes\n", producedSize);
        write_data_to_file(out_path, (uint8_t*)dst, producedSize);
        free(dst);
        return 0;
    }

    if (method == 6) { // XZ
        tools_logi(" Detected XZ format. Decompressing...\n");
        
        uint8_t *xz_dst = NULL;
        uint32_t xz_size = 0;

        if (decompress_xz(data, size, &xz_dst, &xz_size) == 0) {
            tools_logi("XZ Decompressed: %u bytes\n", xz_size);
            write_data_to_file(out_path, xz_dst, xz_size);
            free(xz_dst); 
            return 0;
        } else {
            tools_loge(" XZ Decompression failed.\n");
            return -1;
        }
    }

    if (method == 7) { // LZMA Legacy
        tools_logi("Detected Legacy LZMA format. Decompressing...\n");
        
        uint8_t *lzma_dst = NULL;
        uint32_t lzma_size = 0;

        if (decompress_lzma(data, size, &lzma_dst, &lzma_size) == 0) {
            tools_logi(" LZMA Decompressed: %u bytes\n", lzma_size);
            write_data_to_file(out_path, lzma_dst, lzma_size);
            free(lzma_dst);
            return 0;
        } else {
            tools_loge(" LZMA Decompression failed.\n");
            return -1;
        }
    }

    tools_logi("Treating as Raw Kernel (or unknown format).\n");
    if (write_data_to_file(out_path, data, size) == 0) {
        tools_logi(" Saved raw kernel to %s\n", out_path);
        return 0;
    }

    return -1;
}

int extract_kernel(const char *bootimg_path) {
    FILE *fp = fopen(bootimg_path, "rb");
    if (!fp) {
        tools_logi("Error: Cannot open %s\n", bootimg_path);
        return -1;
    }
    
    struct boot_img_hdr hdr;
    fread(&hdr, sizeof(hdr), 1, fp);

    if (memcmp(hdr.magic, "ANDROID!", 8) != 0) {
        tools_logi("Error: Invalid boot image magic.\n");
        fclose(fp);
        return -2;
    }

    uint32_t kernel_offset = hdr.page_size;
    if (hdr.unused[0] >= 3) {
        kernel_offset = 4096;
    }

    tools_logi("Kernel size: %d, Offset: %d\n", hdr.kernel_size, kernel_offset);

    uint8_t *kernel_data = malloc(hdr.kernel_size);
    if (!kernel_data) {
        fclose(fp);
        return -3;
    }

    fseek(fp, kernel_offset, SEEK_SET);
    fread(kernel_data, 1, hdr.kernel_size, fp);
    fclose(fp);

    int res = auto_depress(kernel_data, hdr.kernel_size, "kernel");

    free(kernel_data);
    return res;
}

int detect_compress_method(compress_head data) {
    // 1. GZIP / ZOPFLI (1F 8B)
    if (data.magic[0] == 0x1F && data.magic[1] == 0x8B) return 1;

    // 2. LZ4 (04 22 4D 18 is Frame )
    if (data.magic[0] == 0x04 && data.magic[1] == 0x22 && 
        data.magic[2] == 0x4D && data.magic[3] == 0x18) return 2;
    // LZ4 Legacy (02 21 4C 18)
    if (data.magic[0] == 0x02 && data.magic[1] == 0x21 && 
        data.magic[2] == 0x4C && data.magic[3] == 0x18) return 3;

    // 3. ZSTD  28 B5 2F FD
    if (data.magic[0] == 0x28 && data.magic[1] == 0xB5 && 
        data.magic[2] == 0x2F && data.magic[3] == 0xFD) return 4;

    // 4. BZIP2 (BZh) - 42 5A 68
    if (data.magic[0] == 0x42 && data.magic[1] == 0x5A && 
        data.magic[2] == 0x68) return 5;

    // 5. XZ - FD 37 7A 58 5A 00
    if (data.magic[0] == 0xFD && data.magic[1] == 0x37 && 
        data.magic[2] == 0x7A && data.magic[3] == 0x58) return 6;

    // 6. LZMA - 5D 00 00
    if (data.magic[0] == 0x5D && data.magic[1] == 0x00 && 
        data.magic[2] == 0x00) return 7;

    return 0; // Raw Kernel
}

int repack_bootimg(const char *orig_boot_path, 
                   const char *new_kernel_path, 
                   const char *out_boot_path) {
    tools_logi(" Starting automatic repack...\n");

    FILE *f_orig = fopen(orig_boot_path, "rb");
    if (!f_orig) return -1;

    struct boot_img_hdr hdr;
    fread(&hdr, sizeof(hdr), 1, f_orig);

    if (memcmp(hdr.magic, "ANDROID!", 8) != 0) {
        tools_logi("Not a valid Android Boot Image.\n");
        fclose(f_orig);
        return -2;
    }

    fseek(f_orig, 0, SEEK_END);
    long total_size = ftell(f_orig);

    uint8_t *foot_buf = NULL;
    foot_buf = malloc(64);
    fseek(f_orig, total_size-64, SEEK_SET);
    fread(foot_buf, 1, 64, f_orig);

    uint32_t header_ver = hdr.unused[0]; 
    uint32_t page_size = (header_ver >= 3) ? 4096 : hdr.page_size;
    tools_logi("Header Version: %u, Page Size: %u\n", header_ver, page_size);

    uint8_t *old_k_full = malloc(hdr.kernel_size);
    fseek(f_orig, page_size, SEEK_SET);
    fread(old_k_full, 1, hdr.kernel_size, f_orig);


    compress_head k_head;
    memcpy(&k_head, old_k_full, sizeof(k_head));
    int method = detect_compress_method(k_head);

    //  DTB (v1/v2)
    uint8_t *extracted_dtb = NULL;
    uint32_t dtb_size = 0;
    if (header_ver < 3) {
        int dtb_off = find_dtb_offset(old_k_full, hdr.kernel_size);
        if (dtb_off > 0) {
            dtb_size = hdr.kernel_size - dtb_off;
            extracted_dtb = malloc(dtb_size);
            memcpy(extracted_dtb, old_k_full + dtb_off, dtb_size);
            tools_logi("Detected DTB appended to kernel. Size: %u\n", dtb_size);
        }
    }
    free(old_k_full); 


    FILE *f_new_k = fopen(new_kernel_path, "rb");
    if (!f_new_k) { fclose(f_orig); if(extracted_dtb) free(extracted_dtb); return -3; }
    fseek(f_new_k, 0, SEEK_END);
    uint32_t raw_k_size = ftell(f_new_k);
    fseek(f_new_k, 0, SEEK_SET);
    uint8_t *raw_k_buf = malloc(raw_k_size);
    fread(raw_k_buf, 1, raw_k_size, f_new_k);
    fclose(f_new_k);

    uint8_t *final_k_buf = raw_k_buf;
    uint32_t final_k_size = raw_k_size;
    uint8_t *compressed_buf = NULL;

    if (method == 1) { 
        tools_logi("Compressing new kernel with GZIP...\n");
        if (compress_gzip(raw_k_buf, raw_k_size, &compressed_buf, &final_k_size) == 0) {
            final_k_buf = compressed_buf;
        }
    }
    if (method == 2) { 
        tools_logi("Compressing new kernel with LZ4...\n");
        if (compress_lz4(raw_k_buf, raw_k_size, &compressed_buf, &final_k_size) == 0) {
            final_k_buf = compressed_buf;
        }
    }
    if (method == 3) { 
        tools_logi("Compressing new kernel with LZ4 Legacy...\n");
        if (compress_lz4_le(raw_k_buf, raw_k_size, &compressed_buf, &final_k_size) == 0) {
            final_k_buf = compressed_buf;
        }
    }
    if (method == 4) {
        tools_logi(" Kernel uses zstd, we have not supported it yet, please report to dev\n");
        return -1;
    }

    if (method == 5) { // BZIP2
        tools_logi(" Compressing new kernel with BZIP2 (Level 9)...\n");

        unsigned int max_out_size = (unsigned int)(raw_k_size * 1.01) + 600;
        uint8_t *compressed_buf = (uint8_t *)malloc(max_out_size);
        if (!compressed_buf) return -1;

        unsigned int final_size = max_out_size;
        unsigned int source_size = (unsigned int)raw_k_size;

        int ret = BZ2_bzBuffToBuffCompress((char*)compressed_buf, &final_size, (char*)raw_k_buf, source_size, 9, 0, 30);

        if (ret == BZ_OK) {
            final_k_buf = compressed_buf;
            final_k_size = final_size;
            tools_logi("BZIP2 compression complete. Size: %u bytes\n", final_k_size);
        } else {
            tools_loge("BZIP2 compression failed: %d\n", ret);
            free(compressed_buf);
            return -1;
        }
    }
    if (method == 6 || method == 7) { 
        tools_logi(" Original was XZ/LZMA. Repacking as GZIP for compatibility...\n");
        uint8_t *compressed_buf = NULL;
        uint32_t final_k_size = 0;
        if (compress_gzip(raw_k_buf, raw_k_size, &compressed_buf, &final_k_size) == 0) {
            final_k_buf = compressed_buf;
            method = 1; 
            tools_logi("Repacked as GZIP. New Size: %u bytes\n", final_k_size);
        } else {
            tools_loge("GZIP compression failed during XZ-to-GZIP conversion.\n");
            return -1;
        }
    }

    uint32_t old_k_aligned = ALIGN(hdr.kernel_size, page_size);
    uint32_t rest_data_offset = page_size + old_k_aligned;
    uint32_t rest_data_size = (total_size > rest_data_offset) ? (total_size - rest_data_offset) : 0;

    uint8_t *rest_buf = NULL;
    if (rest_data_size > 0) {
        rest_buf = malloc(rest_data_size);
        fseek(f_orig, rest_data_offset, SEEK_SET);
        fread(rest_buf, 1, rest_data_size, f_orig);
    }
    fclose(f_orig);


    FILE *f_out = fopen(out_boot_path, "wb");
    if (!f_out) { return -4; }

    hdr.kernel_size = final_k_size + dtb_size;
    fwrite(&hdr, sizeof(hdr), 1, f_out);

    fseek(f_out, page_size, SEEK_SET);


    fwrite(final_k_buf, 1, final_k_size, f_out);
    if (extracted_dtb) {
        fwrite(extracted_dtb, 1, dtb_size, f_out);
    }
    tools_logi("dtb_size=%d\n",dtb_size);

    uint32_t new_k_total_aligned = ALIGN(hdr.kernel_size, page_size);
    fseek(f_out, page_size + new_k_total_aligned, SEEK_SET);
    //tools_logi("rest_data_size=%d,total_size=%d,rest_data_offset=%d,now=%d\n",rest_data_size , total_size , rest_data_offset,page_size + new_k_total_aligned);
    if (rest_buf) {
        if (rest_data_size > total_size - page_size - new_k_total_aligned){
            fwrite(rest_buf, 1, total_size - page_size - new_k_total_aligned -64, f_out);
            fwrite(foot_buf, 1, 64 , f_out);
        }else{
            fwrite(rest_buf, 1, rest_data_size, f_out);
        }
    }

    //  Padding
    long current_pos = ftell(f_out);
    //tools_logi("current_post=%d,total_size=%d\n",current_pos,total_size);
    if (current_pos < total_size) {
        uint32_t padding = total_size - current_pos;
        uint8_t *zero_pad = calloc(1, padding);
        fwrite(zero_pad, 1, padding, f_out);
        free(zero_pad);
    }

    fclose(f_out);
    if (compressed_buf) free(compressed_buf);
    if (extracted_dtb) free(extracted_dtb);
    free(raw_k_buf);
    if (rest_buf) free(rest_buf);

    tools_logi("Repack completed: %s\n", out_boot_path);
    return 0;
}
