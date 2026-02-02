// we need  zlib-devel liblz4-devel liblzma-devel
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>

#include "bootimg.h"
#include "common.h"



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


int auto_depress(const uint8_t *data, size_t size, const char *out_path) {
    if (size < 4) return -1;
    compress_head k_head;
    memcpy(&k_head, data, sizeof(k_head));
    int method = detect_compress_method(k_head);

    
    if (method == 1) { //Gzip
        tools_logi("[Info] Detected GZIP compressed kernel.\n");
        if (decompress_gzip(data, size, out_path) == 0) {
            tools_logi("[Success] Decompressed to %s\n", out_path);
            return 0;
        } else {
            tools_logi("[Error] Gzip decompression failed.\n");
            return -1;
        }
    }
    
 
    if (method == 2) { //LZ4 Frame
        tools_logi("[Info] Detected LZ4 compressed kernel.\n");
        char lz4_path[128];
        snprintf(lz4_path, sizeof(lz4_path), "%s.lz4", out_path);
        write_data_to_file(lz4_path, data, size);
        tools_logi("[Action] Saved as %s (Please use 'lz4 -d' to decompress manually if liblz4 code is not added)\n", lz4_path);
        return 1;
    }


    tools_logi("[Info] Treating as Raw Kernel (or unknown format).\n");
    if (write_data_to_file(out_path, data, size) == 0) {
        tools_logi("[Success] Saved raw kernel to %s\n", out_path);
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

int detect_compress_method(compress_head data){
    if (data.magic[0] == 0x1F && data.magic[1] == 0x8B) return 1; // GZIP
    if (data.magic[0] == 0x04 && data.magic[1] == 0x22 && 
        data.magic[2] == 0x4D && data.magic[3] == 0x18) return 2; // LZ4
    return 0;
}


int repack_bootimg(const char *orig_boot_path, 
                        const char *new_kernel_path, 
                        const char *out_boot_path) {
    tools_logi("[Process] Starting automatic repack...\n");

    FILE *f_orig = fopen(orig_boot_path, "rb");
    if (!f_orig) return -1;

    struct boot_img_hdr hdr;
    fread(&hdr, sizeof(hdr), 1, f_orig);

    if (memcmp(hdr.magic, "ANDROID!", 8) != 0) {
        tools_logi("[Error] Not a valid Android Boot Image.\n");
        fclose(f_orig);
        return -2;
    }

    fseek(f_orig, 0, SEEK_END);
    long total_size = ftell(f_orig);


    uint32_t header_ver = hdr.unused[0]; 
    uint32_t page_size = (header_ver >= 3) ? 4096 : hdr.page_size;
    
    tools_logi("[Info] Header Version: %u, Page Size: %u\n", header_ver, page_size);

 
    compress_head k_head;
    fseek(f_orig, page_size, SEEK_SET);
    fread(&k_head, 1, sizeof(k_head), f_orig);
    int method = detect_compress_method(k_head);


    FILE *f_new_k = fopen(new_kernel_path, "rb");
    if (!f_new_k) { fclose(f_orig); return -3; }
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
        tools_logi("[Info] Original was GZIP, compressing new kernel...\n");
        if (compress_gzip(raw_k_buf, raw_k_size, &compressed_buf, &final_k_size) == 0) {
            final_k_buf = compressed_buf;
        }
    }

 
    uint32_t old_k_aligned = ALIGN(hdr.kernel_size, page_size);
    uint32_t rest_data_offset = page_size + old_k_aligned;
    uint32_t rest_data_size = total_size - rest_data_offset;

    uint8_t *rest_buf = NULL;
    if (rest_data_size > 0) {
        rest_buf = malloc(rest_data_size);
        fseek(f_orig, rest_data_offset, SEEK_SET);
        fread(rest_buf, 1, rest_data_size, f_orig);
    }
    fclose(f_orig);


    FILE *f_out = fopen(out_boot_path, "wb");
    if (!f_out) { return -4; }


    hdr.kernel_size = final_k_size;
    fwrite(&hdr, sizeof(hdr), 1, f_out);


    fseek(f_out, page_size, SEEK_SET);


    fwrite(final_k_buf, 1, final_k_size, f_out);


    uint32_t new_k_aligned = ALIGN(final_k_size, page_size);
    fseek(f_out, page_size + new_k_aligned, SEEK_SET);
    if (rest_buf) {
        fwrite(rest_buf, 1, rest_data_size, f_out);
    }

    // Padding
    long current_pos = ftell(f_out);
    if (current_pos < total_size) {
        uint32_t padding = total_size - current_pos;
        uint8_t *zero_pad = calloc(1, padding);
        fwrite(zero_pad, 1, padding, f_out);
        free(zero_pad);
    }

    fclose(f_out);
    if (compressed_buf) free(compressed_buf);
    free(raw_k_buf);
    if (rest_buf) free(rest_buf);

    tools_logi("[Success] Repack completed: %s\n", out_boot_path);
    return 0;
}

