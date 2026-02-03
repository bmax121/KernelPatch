// we need  zlib-devel liblz4-devel liblzma-devel
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>

#include "bootimg.h"
#include "common.h"

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

    uint8_t *foot_buf = NULL;
    foot_buf = malloc(64);
    fseek(f_orig, total_size-64, SEEK_SET);
    fread(foot_buf, 1, 64, f_orig);

    uint32_t header_ver = hdr.unused[0]; 
    uint32_t page_size = (header_ver >= 3) ? 4096 : hdr.page_size;
    tools_logi("[Info] Header Version: %u, Page Size: %u\n", header_ver, page_size);

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
            tools_logi("[Info] Detected DTB appended to kernel. Size: %u\n", dtb_size);
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
        tools_logi("[Info] Compressing new kernel with GZIP...\n");
        if (compress_gzip(raw_k_buf, raw_k_size, &compressed_buf, &final_k_size) == 0) {
            final_k_buf = compressed_buf;
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

    tools_logi("[Success] Repack completed: %s\n", out_boot_path);
    return 0;
}
