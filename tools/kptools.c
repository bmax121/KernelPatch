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

#include "../version"

#include "preset.h"
#include "image.h"
#include "order.h"
#include "kallsym.h"

#define align_floor(x, align) ((uint64_t)(x) & ~((uint64_t)(align)-1))
#define align_ceil(x, align) (((uint64_t)(x) + (uint64_t)(align)-1) & ~((uint64_t)(align)-1))

#define INSN_IS_B(inst) (((inst) & 0xFC000000) == 0x14000000)

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

static uint32_t version = 0;

static char image[FILENAME_MAX] = { '\0' };
static char out[FILENAME_MAX] = { '\0' };
static char kpimg[FILENAME_MAX] = { '\0' };
static char superkey[SUPER_KEY_LEN] = { '\0' };

static kernel_info_t kinfo;
static kallsym_t kallsym;

void print_usage()
{
    char *c = "\nkptools. Kernel Image Patch Tools. "
              "version: %x\n"
              "\n"
              "Usage: ./kptools ...\n"
              "  -h, --help\n"
              "    Print this message.\n"
              "\n"
              "  -p, --patch <kernel_image> <--kpimg kpimg> <--skey super_key> [--out image_patched]\n"
              "  Patch kernel_image with kpimg.\n"
              "    If --out is not specified, default ${kernel_image}__patched will be used.\n"
              "    super_key: Authentication key for supercall system call.\n"
              "\n"
              "  -d, --dump <kernel_image>\n"
              "    Analyze and dump kallsyms infomations of kernel_image to stdout.\n"
              "\n";
    fprintf(stdout, c, version);
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
        fprintf(stdout, "analyze_kallsym_info error\n");
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

static void print_kpimg_info(const char *img)
{
    setup_header_t *header = (setup_header_t *)img;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    fprintf(stdout, "[+] kptools kpimg version: %x\n", ver_num);
    fprintf(stdout, "[+] kptools kpimg compile time: %s\n", header->compile_time);
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

static int32_t get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset(info, img, symbol);
    return offset > 0 ? offset : 0;
}

struct on_each_symbol_struct
{
    const char *symbol;
    uint64_t addr;
};

static int32_t on_each_symbol_callbackup(int32_t index, char type, const char *symbol, int32_t offset, void *userdata)
{
    struct on_each_symbol_struct *data = (struct on_each_symbol_struct *)userdata;
    int len = strlen(data->symbol);
    if (strstr(symbol, data->symbol) == symbol && (symbol[len] == '.' || symbol[len] == '$')) {
        fprintf(stdout, "[+] kallsyms %s -> %s: type: %c, offset: 0x%08x\n", data->symbol, symbol, type, offset);
        data->addr = offset;
        return 1;
    }
    return 0;
}

static int32_t find_suffixed_symbol(kallsym_t *kallsym, char *img_buf, const char *symbol)
{
    struct on_each_symbol_struct udata = { symbol, 0 };
    on_each_symbol(kallsym, img_buf, &udata, on_each_symbol_callbackup);
    return udata.addr;
}

static int fillin_patch_symbol(kallsym_t *kallsym, char *img_buf, patch_symbol_t *symbol, int32_t target_is_be)
{
    symbol->panic = get_symbol_offset_zero(kallsym, img_buf, "panic");

    symbol->rest_init = get_symbol_offset_zero(kallsym, img_buf, "rest_init");
    symbol->cgroup_init = get_symbol_offset_zero(kallsym, img_buf, "cgroup_init");
    if (!symbol->rest_init && !symbol->cgroup_init) {
        symbol->rest_init = find_suffixed_symbol(kallsym, img_buf, "rest_init");
    }
    if (!symbol->rest_init && !symbol->cgroup_init) return -1;

    symbol->kernel_init = get_symbol_offset_zero(kallsym, img_buf, "kernel_init");

    symbol->report_cfi_failure = get_symbol_offset_zero(kallsym, img_buf, "report_cfi_failure");
    symbol->__cfi_slowpath_diag = get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath_diag");
    symbol->__cfi_slowpath = get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath");

    symbol->copy_process = get_symbol_offset_zero(kallsym, img_buf, "copy_process");
    symbol->cgroup_post_fork = get_symbol_offset_zero(kallsym, img_buf, "cgroup_post_fork");
    if (!symbol->copy_process && !symbol->cgroup_post_fork) {
        symbol->copy_process = find_suffixed_symbol(kallsym, img_buf, "copy_process");
    }
    if (!symbol->copy_process && !symbol->cgroup_post_fork) return -1;

    symbol->__do_execve_file = get_symbol_offset_zero(kallsym, img_buf, "__do_execve_file");
    symbol->do_execveat_common = get_symbol_offset_zero(kallsym, img_buf, "do_execveat_common");
    symbol->do_execve_common = get_symbol_offset_zero(kallsym, img_buf, "do_execve_common");
    if (!symbol->__do_execve_file && !symbol->do_execveat_common && !symbol->do_execve_common) {
        symbol->__do_execve_file = find_suffixed_symbol(kallsym, img_buf, "__do_execve_file");
        symbol->do_execveat_common = find_suffixed_symbol(kallsym, img_buf, "do_execveat_common");
        symbol->do_execve_common = find_suffixed_symbol(kallsym, img_buf, "do_execve_common");
    }
    if (!symbol->__do_execve_file && !symbol->do_execveat_common && !symbol->do_execve_common) return -1;

    symbol->avc_denied = get_symbol_offset_zero(kallsym, img_buf, "avc_denied");
    if (!symbol->avc_denied) {
        // gcc -fipa-sra eg: avc_denied.isra.5
        symbol->avc_denied = find_suffixed_symbol(kallsym, img_buf, "avc_denied");
    }
    if (!symbol->avc_denied) return -1;
    symbol->slow_avc_audit = get_symbol_offset_zero(kallsym, img_buf, "slow_avc_audit");

    symbol->input_handle_event = get_symbol_offset_zero(kallsym, img_buf, "input_handle_event");

    symbol->vfs_statx = get_symbol_offset_zero(kallsym, img_buf, "vfs_statx");
    symbol->do_statx = get_symbol_offset_zero(kallsym, img_buf, "do_statx");
    symbol->vfs_fstatat = get_symbol_offset_zero(kallsym, img_buf, "vfs_fstatat");
    if (!symbol->vfs_statx && !symbol->do_statx && !symbol->vfs_fstatat) {
        symbol->vfs_statx = find_suffixed_symbol(kallsym, img_buf, "vfs_statx");
        symbol->do_statx = find_suffixed_symbol(kallsym, img_buf, "do_statx");
        symbol->vfs_fstatat = find_suffixed_symbol(kallsym, img_buf, "vfs_fstatat");
    }
    if (!symbol->vfs_statx && !symbol->do_statx && !symbol->vfs_fstatat) return -1;

    symbol->do_faccessat = get_symbol_offset_zero(kallsym, img_buf, "do_faccessat");
    symbol->sys_faccessat = get_symbol_offset_zero(kallsym, img_buf, "sys_faccessat");
    if (!symbol->do_faccessat && !symbol->sys_faccessat) {
        symbol->do_faccessat = find_suffixed_symbol(kallsym, img_buf, "do_faccessat");
        symbol->sys_faccessat = find_suffixed_symbol(kallsym, img_buf, "sys_faccessat");
    }
    if (!symbol->do_faccessat && !symbol->sys_faccessat) return -1;

    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos <= (int64_t *)symbol; pos++) {
            *pos = i64swp(*pos);
        }
    }

    return 0;
}

// todo
void select_map_area(kallsym_t *kallsym, char *image_buf, int32_t *map_start, int32_t *max_size)
{
    int32_t addr = 0x200;
    addr = get_symbol_offset(kallsym, image_buf, "tcp_init_sock");
    *map_start = align_ceil(addr, 16);
    *max_size = 0x800;
}

int patch_image()
{
    if (!strlen(out)) {
        strcpy(out, image);
        strcat(out, "_patched");
    }
    if (!strlen(kpimg)) {
        fprintf(stdout, "[-] kptools kpimg not specified\n");
        return EXIT_FAILURE;
    }

    FILE *fimage = fopen(image, "rb");
    if (!fimage) {
        fprintf(stdout, "[-] kptools open file %s error\n", image);
        return EXIT_FAILURE;
    }
    fseek(fimage, 0, SEEK_END);
    long image_len = ftell(fimage);
    fprintf(stdout, "[+] kptools image size 0x%08lx\n", image_len);

    fseek(fimage, 0, SEEK_SET);

    char *image_buf = (char *)malloc(image_len);
    fread(image_buf, 1, image_len, fimage);
    fclose(fimage);

    FILE *fkpimg = fopen(kpimg, "rb");
    if (!fkpimg) {
        fprintf(stdout, "[-] kptools open file %s error\n", kpimg);
        return EXIT_FAILURE;
    }
    fseek(fimage, 0, SEEK_END);
    long kpimg_len = ftell(fimage);
    fseek(fkpimg, 0, SEEK_SET);
    fprintf(stdout, "[+] kptools kernel patch image size: 0x%08lx\n", kpimg_len);

    long align_image_len = align_ceil(image_len, 4096);
    long out_len = align_image_len + kpimg_len;

    char *out_buf = (char *)malloc(out_len);
    memset(out_buf, 0, out_len);
    memcpy(out_buf, image_buf, image_len);
    fread(out_buf + align_image_len, 1, kpimg_len, fkpimg);
    fclose(fkpimg);

    print_kpimg_info(out_buf + align_image_len);

    if (get_kernel_info(&kinfo, image_buf, image_len)) {
        fprintf(stdout, "[-] kptools is %s a kernel image?\n", image);
        return -1;
    }
    long align_kernel_size = align_ceil(kinfo.kernel_size, 4096);

    fprintf(stdout, "[+] kptools kernel new size 0x%08lx\n", align_kernel_size + kpimg_len);

    if (analyze_kallsym_info(&kallsym, image_buf, image_len, ARM64, 1)) {
        fprintf(stdout, "[-] kptools analyze_kallsym_info error\n");
        return -1;
    }

    setup_preset_t *preset = (setup_preset_t *)(out_buf + align_image_len + KP_HEADER_SIZE);
    memset(preset, 0, sizeof(setup_preset_t));

    preset->kernel_size = kinfo.kernel_size;
    preset->start_offset = align_kernel_size;
    preset->page_shift = kinfo.page_shift;
    preset->kernel_version.major = kallsym.version.major;
    preset->kernel_version.minor = kallsym.version.minor;
    preset->kernel_version.patch = kallsym.version.patch;

    memcpy(preset->header_backup, out_buf, sizeof(preset->header_backup));
    preset->kp_offset = align_image_len;

    int32_t map_start, map_max_size;
    select_map_area(&kallsym, image_buf, &map_start, &map_max_size);
    preset->map_offset = map_start;
    preset->map_max_size = map_max_size;
    fprintf(stdout, "[+] kptools map_start: 0x%x, max_size: 0x%x\n", map_start, map_max_size);

    preset->kallsyms_lookup_name_offset = get_symbol_offset(&kallsym, image_buf, "kallsyms_lookup_name");

    preset->printk_offset = get_symbol_offset(&kallsym, image_buf, "printk");
    if (preset->printk_offset < 0) preset->printk_offset = get_symbol_offset(&kallsym, image_buf, "_printk");

    int32_t paging_init_offset = get_symbol_offset(&kallsym, image_buf, "paging_init");
    preset->paging_init_offset = relo_branch_func(image_buf, paging_init_offset);

    preset->memblock_reserve_offset = get_symbol_offset(&kallsym, image_buf, "memblock_reserve");

    preset->memblock_alloc_try_nid_offset = get_symbol_offset(&kallsym, image_buf, "memblock_phys_alloc_try_nid");
    if (preset->memblock_alloc_try_nid_offset <= 0)
        preset->memblock_alloc_try_nid_offset = get_symbol_offset(&kallsym, image_buf, "memblock_alloc_try_nid");

    preset->memblock_mark_nomap_offset = get_symbol_offset(&kallsym, image_buf, "memblock_mark_nomap");
    if (preset->memblock_mark_nomap_offset < 0) {
        preset->memblock_mark_nomap_offset = 0;
    }

    preset->memstart_addr_offset = get_symbol_offset(&kallsym, image_buf, "memstart_addr");
    if (preset->memstart_addr_offset < 0) preset->memstart_addr_offset = 0;
    if (!preset->memstart_addr_offset) {
        fprintf(stdout, "[!] kptools ==== warring ====\n");
        fprintf(stdout, "[!] kptools ==== warring ====\n");
        fprintf(stdout, "[!] kptools It seems that CONFIG_KALLSYMS_ALL=y is not enabled in the kernel.\n");
        fprintf(stdout, "[!] kptools It is recommended that you do not flash it and wait for support.\n");
        fprintf(stdout, "[!] kptools ==== warring ====\n");
        fprintf(stdout, "[!] kptools ==== warring ====\n");
        return -1;
    }

    if (kallsym.version.major >= 6) preset->vabits_flag = 1;
    if (get_symbol_offset(&kallsym, image_buf, "vabits_actual") > 0) preset->vabits_flag = 1;

    preset->kimage_voffset_offset = get_symbol_offset(&kallsym, image_buf, "kimage_voffset");
    if (preset->kimage_voffset_offset < 0) preset->kimage_voffset_offset = 0;

    if (strlen(superkey) > 0) {
        strncpy((char *)preset->superkey, superkey, SUPER_KEY_LEN);
    } else {
        fprintf(stdout, "[?] kptools warnning use default key is dangerous!\n");
        strcpy((char *)preset->superkey, "kernel_patch");
    }
    fprintf(stdout, "[+] kptools supercall key: %s\n", preset->superkey);

    patch_symbol_t *symbol = &preset->patch_symbol;

    int rc = fillin_patch_symbol(&kallsym, image_buf, symbol, kinfo.is_be);
    if (rc) {
        fprintf(stdout, "[-] kptools fillin_patch_symbol error\n");
        return EXIT_FAILURE;
    }

    patch_config_t *config = &preset->patch_config;
#ifdef ANDROID
    strncpy(config->config_reserved, "/data/adb/ap/init.ini", sizeof(config->config_reserved) - 1);
#else
    strncpy(config->config_reserved, "/etc/kp/init.ini", sizeof(config->config_reserved) - 1);
#endif

    // todo:
    // kernel_resize(&kinfo, out_buf, align_kernel_size + align_image_len);
    long text_offset = align_image_len + 4096;

    b((uint32_t *)(out_buf + kinfo.b_stext_insn_offset), kinfo.b_stext_insn_offset, text_offset);

    target_endian_preset(preset, kinfo.is_be);

    FILE *fout = fopen(out, "wb");
    if (!fout) {
        fprintf(stdout, "[-] kptools open file:%s error\n", out);
        return EXIT_FAILURE;
    }
    fwrite(out_buf, out_len, 1, fout);
    fclose(fout);
    fprintf(stdout, "[+] kptools patch done: %s\n", out);
    return 0;
}

int main(int argc, char *argv[])
{
    version = (MAJOR << 16) + (MINOR << 8) + PATCH;
    fprintf(stdout, "[+] kptools version: %x\n", version);

    struct option longopts[] = { { "version", no_argument, NULL, 'v' },     { "help", no_argument, NULL, 'h' },
                                 { "patch", required_argument, NULL, 'p' }, { "skey", required_argument, NULL, 's' },
                                 { "out", required_argument, NULL, 'o' },   { "kpimg", required_argument, NULL, 'k' },
                                 { "dump", required_argument, NULL, 'd' },  { 0, 0, 0, 0 } };
    char *optstr = "vhp:d:o:";

    int cmd = '\0';
    int opt = -1;
    int opt_index = -1;
    while ((opt = getopt_long(argc, argv, optstr, longopts, &opt_index)) != -1) {
        switch (opt) {
        case 'v':
            cmd = 'v';
            break;
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
    } else if (cmd == 'v') {
        fprintf(stdout, "%x\n", version);
    } else {
        print_usage();
    }
    return ret;
}
