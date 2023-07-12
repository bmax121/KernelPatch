
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "../kernel/base/preset.h"
#include "image.h"
#include "order.h"
#include "kallsym.h"

#define align_floor(x, align) ((uint64_t)(x) & ~((uint64_t)(align)-1))
#define align_ceil(x, align) (((uint64_t)(x) + (uint64_t)(align)-1) & ~((uint64_t)(align)-1))

#define INSN_IS_B(inst) (((inst)&0xFC000000) == 0x14000000)

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))

#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)

static int can_b_imm(uint64_t from, uint64_t to)
{
    // B: 128M
    uint32_t imm26 = 1 << 25 << 2;
    return (to >= from && to - from <= imm26) || (from >= to && from - to <= imm26);
}

static int b(uint32_t *buf, uint64_t from, uint64_t to)
{
    if (can_b_imm(from, to)) {
        buf[0] = 0x14000000u | (((to - from) & 0x0FFFFFFFu) >> 2u);
        return 4;
    }
    return 0;
}

static char image[FILENAME_MAX] = { '\0' };
static char out[FILENAME_MAX] = { '\0' };
static char kpimg[FILENAME_MAX] = { '\0' };
static char superkey[SUPER_KEY_LEN] = { '\0' };

static kernel_info_t kinfo;
static kallsym_t kallsym;

void print_usage()
{
    char *c = "\nkptools. Kernel Image Patch Tools.\n"
              "\n"
              "Usage: ./kptools <command> [args...]\n"
              "  -h, --help\n"
              "    Print this message.\n"
              "\n"
              "  -p, --patch <kernel_image> <--kpimg kp.bin> <--skey your_key> [--out image_patched]\n"
              "  Patch kernel_image with kp.bin to image_patched.\n"
              "    If [--out] is not specified, default ${kernel_image}__patched will be used.\n"
              "    <--skey>: Authentication key for supercall system call.\n"
              "\n"
              "  -d, --dump <kernel_image>\n"
              "    Analyze and dump kallsyms infomations of kernel_image to stdout.\n"
              "\n";
    fprintf(stdout, "%s", c);
}

int dump_kallsym()
{
    FILE *fin = fopen(image, "rb");
    if (!fin) {
        printf("[-] read file %s error\n", image);
        return EXIT_FAILURE;
    }
    fseek(fin, 0, SEEK_END);
    long image_len = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    char *image_buf = (char *)malloc(image_len);
    fread(image_buf, 1, image_len, fin);

    kallsym_t kallsym;
    if (analyze_kallsym_info(&kallsym, image_buf, image_len, ARM64, 1)) {
        fprintf(stderr, "analyze_kallsym_info error\n");
        return -1;
    }
    dump_all_symbols(&kallsym, image_buf);
    free(image_buf);
    return 0;
}

static int32_t relo_branch_func(const char *img, int32_t func_offset)
{
    uint32_t inst = *(uint32_t *)(img + func_offset);
    int32_t relo_offset = func_offset;
    if (INSN_IS_B(inst)) {
        uint64_t imm26 = bits32(inst, 25, 0);
        uint64_t imm64 = sign64_extend(imm26 << 2u, 28u);
        relo_offset = func_offset + (int32_t)imm64;
        fprintf(stdout, "[+] kptools relocate branch function 0x%x to 0x%x\n", func_offset, relo_offset);
    }
    return relo_offset;
}

static void target_endian_preset(setup_preset_t *preset, int32_t target_is_be)
{
    if (!(is_be() ^ target_is_be)) return;
    preset->kernel_size = i64swp(preset->kernel_size);
    preset->page_shift = i64swp(preset->page_shift);
    preset->kp_offset = i64swp(preset->kp_offset);
    preset->map_offset = i64swp(preset->map_offset);
    preset->map_max_size = i64swp(preset->map_max_size);
    for (int64_t *pos = (int64_t *)&preset->kallsyms_lookup_name_offset;
         pos <= (int64_t *)&preset->kimage_voffset_offset; pos++) {
        *pos = i64swp(*pos);
    }
}

// todo
void select_map_area(int32_t *map_start, int32_t *max_size)
{
    *map_start = 0x200;
    *max_size = 0x800;
}

int patch_image()
{
    if (!strlen(out)) {
        strcpy(out, image);
        strcat(out, "_patched");
    }
    if (!strlen(kpimg)) {
        fprintf(stderr, "[-] kptools kpimg not specified\n");
        return EXIT_FAILURE;
    }

    FILE *fimage = fopen(image, "rb");
    if (!fimage) {
        printf("[-] kptools open file %s error\n", image);
        return EXIT_FAILURE;
    }
    fseek(fimage, 0, SEEK_END);
    long image_len = ftell(fimage);
    printf("[+] kptools image size 0x%08lx\n", image_len);

    fseek(fimage, 0, SEEK_SET);

    char *image_buf = (char *)malloc(image_len);
    fread(image_buf, 1, image_len, fimage);
    fclose(fimage);

    FILE *fkpimg = fopen(kpimg, "rb");
    if (!fkpimg) {
        printf("[-] kptools open file %s error\n", kpimg);
        return EXIT_FAILURE;
    }
    fseek(fimage, 0, SEEK_END);
    long kpimg_len = ftell(fimage);
    fseek(fkpimg, 0, SEEK_SET);
    fprintf(stdout, "[-] kptools kernel patch image size: 0x%08lx\n", kpimg_len);

    long align_image_len = align_ceil(image_len, 4096);
    long out_len = align_image_len + kpimg_len;

    char *out_buf = (char *)malloc(out_len);
    memset(out_buf, 0, out_len);
    memcpy(out_buf, image_buf, image_len);
    fread(out_buf + align_image_len, 1, kpimg_len, fkpimg);
    fclose(fkpimg);

    get_kernel_info(&kinfo, image_buf, image_len);
    long align_kernel_size = align_ceil(kinfo.kernel_size, 4096);

    printf("[+] kptools kernel new size 0x%08lx\n", align_kernel_size + kpimg_len);

    if (analyze_kallsym_info(&kallsym, image_buf, image_len, ARM64, 1)) {
        fprintf(stderr, "[-] kptools analyze_kallsym_info error\n");
        return -1;
    }

    setup_header_t *sdata = (setup_header_t *)(out_buf + align_image_len);
    setup_preset_t *preset = (setup_preset_t *)(out_buf + align_image_len + 64);

    preset->kernel_size = kinfo.kernel_size;
    preset->start_offset = align_kernel_size;
    preset->page_shift = kinfo.page_shift;
    sdata->kernel_version.major = kallsym.version.major;
    sdata->kernel_version.minor = kallsym.version.minor;
    sdata->kernel_version.patch = kallsym.version.patch;

    memcpy(preset->header_backup, out_buf, sizeof(preset->header_backup));
    preset->kp_offset = align_image_len;

    int32_t map_start, map_max_size;
    select_map_area(&map_start, &map_max_size);
    preset->map_offset = map_start;
    preset->map_max_size = map_max_size;
    fprintf(stdout, "[+] kptools map_start: 0x%x, max_size: 0x%x\n", map_start, map_max_size);

    preset->kallsyms_lookup_name_offset = get_symbol_offset(&kallsym, image_buf, "kallsyms_lookup_name");
    preset->printk_offset = get_symbol_offset(&kallsym, image_buf, "printk");
    int32_t paging_init_offset = get_symbol_offset(&kallsym, image_buf, "paging_init");
    preset->paging_init_offset = relo_branch_func(image_buf, paging_init_offset);
    preset->memblock_reserve_offset = get_symbol_offset(&kallsym, image_buf, "memblock_reserve");
    preset->memblock_alloc_try_nid_offset = get_symbol_offset(&kallsym, image_buf, "memblock_alloc_try_nid");
    if (preset->memblock_alloc_try_nid_offset <= 0)
        preset->memblock_alloc_try_nid_offset = get_symbol_offset(&kallsym, image_buf, "memblock_virt_alloc_try_nid");
    if (preset->memblock_alloc_try_nid_offset <= 0)
        preset->memblock_alloc_try_nid_offset = get_symbol_offset(&kallsym, image_buf, "memblock_phys_alloc_try_nid");
    preset->memstart_addr_offset = get_symbol_offset(&kallsym, image_buf, "memstart_addr");
    if (preset->memstart_addr_offset < 0) preset->memstart_addr_offset = 0;
    preset->vabits_actual_offset = get_symbol_offset(&kallsym, image_buf, "vabits_actual");
    if (preset->vabits_actual_offset < 0) preset->vabits_actual_offset = 0;
    preset->kimage_voffset_offset = get_symbol_offset(&kallsym, image_buf, "kimage_voffset");
    if (preset->kimage_voffset_offset < 0) preset->kimage_voffset_offset = 0;

    if (strlen(superkey) > 0) {
        strncpy((char *)preset->superkey, superkey, SUPER_KEY_LEN);
    } else {
        fprintf(stdout, "[-] kptools warnning use default key is dangerous!\n");
        strcpy((char *)preset->superkey, "kernel_patch");
    }
    fprintf(stdout, "[+] kptools supercall key: %s\n", preset->superkey);

    // todo: need this?
    kernel_resize(&kinfo, out_buf, align_kernel_size + align_image_len);
    long text_offset = align_image_len + 4096;
    b((uint32_t *)(out_buf + kinfo.b_stext_insn_offset), kinfo.b_stext_insn_offset, text_offset);

    target_endian_preset(preset, kinfo.is_be);

    FILE *fout = fopen(out, "wb");
    if (!fout) {
        fprintf(stderr, "[-] kptools open file:%s error\n", out);
        return EXIT_FAILURE;
    }
    fwrite(out_buf, out_len, 1, fout);
    fclose(fout);
    fprintf(stdout, "[+] kptools patch done: %s\n", out);
    return 0;
}

int main(int argc, char *argv[])
{
    // todo: optional_argument not work
    struct option longopts[] = { { "help", no_argument, NULL, 'h' },
                                 { "patch", required_argument, NULL, 'p' },
                                 { "skey", required_argument, NULL, 's' },
                                 { "out", required_argument, NULL, 'o' },
                                 { "kpimg", required_argument, NULL, 'k' },
                                 { "dump", required_argument, NULL, 'd' },
                                 { 0, 0, 0, 0 } };
    char *optstr = "hp:d:o:";

    int cmd = '\0';
    int opt = -1;
    int opt_index = -1;
    while ((opt = getopt_long(argc, argv, optstr, longopts, &opt_index)) != -1) {
        switch (opt) {
        case 'h':
            cmd = 'h';
            break;
        case 'p':
        case 'd':
            cmd = opt;
            strncpy(image, optarg, FILENAME_MAX - 1);
            break;
        case 'o':
            strncpy(out, optarg, FILENAME_MAX - 1);
            break;
        case 'k':
            strncpy(kpimg, optarg, FILENAME_MAX - 1);
            break;
        case 's':
            strncpy(superkey, optarg, SUPER_KEY_LEN);
            break;
        default:
            break;
        }
    }
    int ret = 0;
    if (cmd == 'h') {
        print_usage();
    } else if (cmd == 'p') {
        ret = patch_image();
    } else if (cmd == 'd') {
        ret = dump_kallsym();
    } else {
        print_usage();
    }
    return ret;
}
