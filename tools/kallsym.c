#include "kallsym.h"

#define _GNU_SOURCE
#define __USE_GNU

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define align_floor(x, align) ((uint64_t)(x) & ~((uint64_t)(align)-1))
#define align_ceil(x, align) (((uint64_t)(x) + (uint64_t)(align)-1) & ~((uint64_t)(align)-1))

#include "order.h"

static int64_t int_unpack(void *ptr, int32_t size, int32_t is_be)
{
    int16_t res16;
    int32_t res32;
    int64_t res64;
    switch (size) {
    case 8:
        res64 = *(int64_t *)ptr;
        return is_be ? i64be(res64) : i64le(res64);
    case 4:
        res32 = *(int32_t *)ptr;
        return is_be ? i32be(res32) : i32le(res32);
    case 2:
        res16 = *(int16_t *)ptr;
        return is_be ? i16be(res16) : i16le(res16);
    default:
        return *(int8_t *)ptr;
    }
}

static uint64_t uint_unpack(void *ptr, int32_t size, int32_t is_be)
{
    uint16_t res16;
    uint32_t res32;
    uint64_t res64;
    switch (size) {
    case 8:
        res64 = *(uint64_t *)ptr;
        return is_be ? u64be(res64) : u64le(res64);
    case 4:
        res32 = *(uint32_t *)ptr;
        return is_be ? u32be(res32) : u32le(res32);
    case 2:
        res16 = *(uint16_t *)ptr;
        return is_be ? u16be(res16) : u16le(res16);
    default:
        return *(uint8_t *)ptr;
    }
}

static int find_linux_banner(kallsym_t *info, char *img, int32_t imglen)
{
    /*
	// todo: linux_proc_banner
  const char linux_banner[] =
        "Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@"
        LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n";
  Linux version 4.9.270-g862f51bac900-ab7613625 (android-build@abfarm-east4-101)
  (Android (7284624, based on r416183b) clang version 12.0.5
  (https://android.googlesource.com/toolchain/llvm-project
  c935d99d7cf2016289302412d708641d52d2f7ee)) #0 SMP PREEMPT Thu Aug 5 07:04:42
  UTC 2021
  */
    char linux_banner_prefix[] = "Linux version ";
    size_t prefix_len = strlen(linux_banner_prefix);

    char *imgend = img + imglen;
    char *banner = (char *)img;
    info->banner_num = 0;
    while ((banner = (char *)memmem(banner + 1, imgend - banner, linux_banner_prefix, prefix_len)) != NULL) {
        if (isdigit(*(banner + prefix_len)) && *(banner + prefix_len + 1) == '.') {
            info->linux_banner_offset[info->banner_num++] = (int32_t)(banner - img);
        }
    }

    banner = img + info->linux_banner_offset[info->banner_num - 1];
    fprintf(stdout, "[+] kernel linux_banner num: %d\n", info->banner_num);
    fprintf(stdout, "[+] kernel last linux_banner: %s", banner);

    char *uts_release_start = banner + prefix_len;
    char *space = strchr(banner + prefix_len, ' ');

    char *dot = NULL;
    info->version.major = strtol(uts_release_start, &dot, 10);
    info->version.minor = strtol(dot + 1, &dot, 10);
    info->version.patch = strtol(dot + 1, &dot, 10);

    fprintf(stdout, "[+] kernel version major: %d, minor: %d, patch: %d \n", info->version.major, info->version.minor,
            info->version.patch);
    return 0;
}

static int dump_kernel_config(kallsym_t *info, char *img, int32_t imglen)
{
    // todo:
    /*
  kernel configuration
  when CONFIG_IKCONFIG is enabled
  archived in GZip format between the magic string 'IKCFG_ST' and 'IKCFG_ED' in
  the built kernel.
  */
    fprintf(stdout, "[-] dump_kernel_config not implemented\n");
    return 0;
}

static int find_token_table(kallsym_t *info, char *img, int32_t imglen)
{
    char nums_syms[20] = { '\0' };
    for (int32_t i = 0; i < 10; i++)
        nums_syms[i * 2] = '0' + i;
    // We just check first 10 letters, not all letters are guaranteed to appear,
    // In fact, the previous numbers may not always appear too.
    char letters_syms[20] = { '\0' };
    for (int32_t i = 0; i < 10; i++)
        letters_syms[i * 2] = 'a' + i;

    char *pos = img;
    char *num_start = NULL;
    char *imgend = img + imglen;
    for (; pos < imgend; pos = num_start + 1) {
        num_start = (char *)memmem(pos, imgend - pos, nums_syms, sizeof(nums_syms));
        if (!num_start) {
            fprintf(stderr, "[-] kallsyms find token_table error\n");
            return -1;
        }
        char *num_end = num_start + sizeof(nums_syms);
        if (!*num_end || !*(num_end + 1)) continue;

        char *letter = num_end;
        for (int32_t i = 0; letter < imgend && i < 'a' - '9' - 1; letter++) {
            if (!*letter) i++;
        }
        if (letter != (char *)memmem(letter, sizeof(letters_syms), letters_syms, sizeof(letters_syms))) continue;
        break;
    }

    // backward to start
    pos = num_start;
    for (int32_t i = 0; pos > img && i < '0' + 1; pos--) {
        if (!*pos) i++;
    }
    int32_t offset = pos + 2 - img;

    info->kallsyms_token_table_offset = offset;
    fprintf(stdout, "[+] kallsyms kallsyms_token_table offset: 0x%08x\n", offset);

    // rebuild token_table
    pos = img + info->kallsyms_token_table_offset;
    for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
        info->kallsyms_token_table[i] = pos;
        while (*(pos++)) {
        };
    }
    // fprintf(stdout, "[+] kallsyms token table: ");
    // for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
    //   printf("%s ", info->kallsyms_token_table[i]);
    // }
    // printf("\n");
    return 0;
}

static int find_token_index(kallsym_t *info, char *img, int32_t imglen)
{
    uint16_t le_index[KSYM_TOKEN_NUMS] = { 0 };
    uint16_t be_index[KSYM_TOKEN_NUMS] = { 0 };

    int32_t start = info->kallsyms_token_table_offset;
    int32_t offset = start;

    // build kallsyms_token_index according to kallsyms_token_table
    for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
        uint16_t token_index = offset - start;
        le_index[i] = u16le(token_index);
        be_index[i] = u16be(token_index);
        while (img[offset++]) {
        };
    }
    // find kallsyms_token_index
    char *lepos = (char *)memmem(img, imglen, le_index, sizeof(le_index));
    char *bepos = (char *)memmem(img, imglen, be_index, sizeof(be_index));

    if (!lepos && !bepos) {
        fprintf(stderr, "[-] kallsyms kallsyms_token_index error\n");
        return -1;
    }
    fprintf(stdout, "[+] kallsyms endian: %s\n", lepos ? "little" : "big");

    char *pos = lepos ? lepos : bepos;
    info->is_be = lepos ? 0 : 1;

    info->kallsyms_token_index_offset = pos - img;

    fprintf(stdout, "[+] kallsyms kallsyms_token_index offset: 0x%08x\n", info->kallsyms_token_index_offset);
    return 0;
}

static int get_markers_elem_size(kallsym_t *info)
{
    /*
  Before 4.20, type of kallsyms_markers is PTR which
  depends on macro BITS_PER_LONG. When BITS_PER_LONG is 64, PTR is .quad (8
  bytes), otherwise .long (4bytes). Since 4.20, type of kallsyms_markers is
  .long (4 bytes)
  */
    int32_t elem_size = info->asm_long_size;
    if (info->version.major < 4 || (info->version.major == 4 && info->version.minor < 20))
        elem_size = info->asm_PTR_size;
    return elem_size;
}

static int get_num_syms_elem_size(kallsym_t *info)
{
    // the same as kallsyms_markers
    int32_t elem_size = info->asm_long_size;
    if (info->version.major < 4 || (info->version.major == 4 && info->version.minor < 20))
        elem_size = info->asm_PTR_size;
    return elem_size;
}

static inline int get_addresses_elem_size(kallsym_t *info)
{
    return info->asm_PTR_size;
}

static inline int get_offsets_elem_size(kallsym_t *info)
{
    return info->asm_long_size;
}

static int try_find_arm64_relo_table(kallsym_t *info, char *img, int32_t imglen)
{
    if (!info->try_relo) return 0;
    uint64_t min_va = 0xffffff8008080000;
    uint64_t max_va = 0xffffffffffffffff;
    uint64_t kernel_va = max_va;
    int32_t cand = 0;
    int rela_num = 0;
    while (cand < imglen - 24) {
        uint64_t r_offset = uint_unpack(img + cand, 8, info->is_be);
        uint64_t r_info = uint_unpack(img + cand + 8, 8, info->is_be);
        uint64_t r_addend = uint_unpack(img + cand + 16, 8, info->is_be);
        if ((r_offset & 0xffff000000000000) == 0xffff000000000000 && r_info == 0x403) {
            if (!(r_addend & 0xfff) && r_addend >= min_va && r_addend < kernel_va) kernel_va = r_addend;
            cand += 24;
            rela_num++;
        } else if (rela_num && !r_offset && !r_info && !r_addend) {
            cand += 24;
            rela_num++;
        } else {
            if (rela_num >= ARM64_RELO_MIN_NUM) break;
            cand += 8;
            rela_num = 0;
            kernel_va = max_va;
        }
    }
    int32_t cand_start = cand - 24 * rela_num;
    int32_t cand_end = cand - 24;
    while (1) {
        if (*(uint64_t *)(img + cand_end) && *(uint64_t *)(img + cand_end + 8) && *(uint64_t *)(img + cand_end + 16))
            break;
        cand_end -= 24;
    }
    cand_end += 24;

    rela_num = (cand_end - cand_start) / 24;
    if (rela_num < ARM64_RELO_MIN_NUM) {
        fprintf(stdout, "[-] kallsyms can't find arm64 relocation table\n");
        return 0;
    }
    fprintf(stdout,
            "[+] kallsyms find arm64 relocation table range: [0x%08x, 0x%08x), text_va: 0x%08lx, count: 0x%08x\n",
            cand_start, cand_end, kernel_va, rela_num);

    // apply relocations
    int32_t apply_num = 0;
    for (cand = cand_start; cand < cand_end; cand += 24) {
        uint64_t r_offset = uint_unpack(img + cand, 8, info->is_be);
        uint64_t r_info = uint_unpack(img + cand + 8, 8, info->is_be);
        uint64_t r_addend = uint_unpack(img + cand + 16, 8, info->is_be);
        if (!r_offset && !r_info && !r_addend) continue;
        if (r_offset <= kernel_va || r_offset >= max_va - imglen) {
            // fprintf(stdout, "[-] kallsyms warn ignore arm64 relocation r_offset: 0x%08lx at 0x%08x\n", r_offset, cand);
            continue;
        }
        int32_t offset = r_offset - kernel_va;
        if (offset >= imglen) {
            fprintf(stdout, "[-] kallsyms apply relocations error\n");
            return -1;
        }
        uint64_t value = uint_unpack(img + offset, 8, info->is_be);
        if (value == r_addend) continue;
        *(uint64_t *)(img + offset) = value + r_addend;
        apply_num++;
    }
    if (apply_num) apply_num--;
    fprintf(stdout, "[+] kallsyms apply 0x%08x relocation entries\n", apply_num);

    if (apply_num) info->relo_applied = 1;

// #define KALLSYM_SAVE_RELO
#ifdef KALLSYM_SAVE_RELO
#include <stdio.h>
    FILE *frelo = fopen("/Users/bmax/tmp/kernel.relo", "wb+");
    fwrite(img, imglen, 1, frelo);
    fclose(frelo);
#endif

    return 0;
}

static int find_approx_addresses(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t sym_num = 0;
    int32_t elem_size = info->asm_PTR_size;
    uint64_t prev_offset = 0;
    int32_t cand = 0;

    for (; cand < imglen - KSYM_MIN_NEQ_SYMS * elem_size; cand += elem_size) {
        uint64_t address = uint_unpack(img + cand, elem_size, info->is_be);
        if (!sym_num) { // first address
            if (address & 0xff) continue;
            if (elem_size == 4 && (address & 0xff800000) != 0xff800000) continue;
            if (elem_size == 8 && (address & 0xffff000000000000) != 0xffff000000000000) continue;
            prev_offset = address;
            sym_num++;
            continue;
        }
        if (address >= prev_offset) {
            prev_offset = address;
            if (sym_num++ >= KSYM_MIN_NEQ_SYMS) break;
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
    }
    if (sym_num < KSYM_MIN_NEQ_SYMS) {
        fprintf(stderr, "[-] kallsyms find approximate kallsyms_addresses error\n");
        return -1;
    }

    cand -= KSYM_MIN_NEQ_SYMS * elem_size;
    int32_t approx_offset = cand;
    info->_approx_addresses_or_offsets_offset = approx_offset;

    // approximate kallsyms_addresses end
    prev_offset = 0;
    for (; cand < imglen; cand += elem_size) {
        uint64_t offset = uint_unpack(img + cand, elem_size, info->is_be);
        if (offset < prev_offset) break;
        prev_offset = offset;
    }
    // end is not include
    info->_approx_addresses_or_offsets_end = cand;
    info->has_relative_base = 0;
    int32_t approx_num_syms = (cand - approx_offset) / elem_size;
    info->_approx_addresses_or_offsets_num = approx_num_syms;
    fprintf(stdout,
            "[+] kallsyms approximate kallsyms_addresses range: [0x%08x, 0x%08x) "
            "count: 0x%08x\n",
            approx_offset, cand, approx_num_syms);

    //
    // todo: tmp fix relo error, some bugs
    if (info->relo_applied) {
        fprintf(stdout, "[-] kallsyms Here are some known bug, subsequent operations is undefined\n");
    }

    return 0;
}

static int find_approx_offsets(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t sym_num = 0;
    int32_t elem_size = info->asm_long_size;
    int64_t prev_offset = 0;
    int32_t cand = 0;
    int32_t MAX_ZERO_OFFSET_NUM = 10;
    int32_t zero_offset_num = 0;
    for (; cand < imglen - KSYM_MIN_NEQ_SYMS * elem_size; cand += elem_size) {
        int64_t offset = int_unpack(img + cand, elem_size, info->is_be);
        if (offset == prev_offset) { // 0 offset
            continue;
        } else if (offset > prev_offset) {
            prev_offset = offset;
            if (sym_num++ >= KSYM_MIN_NEQ_SYMS) break;
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
    }
    if (sym_num < KSYM_MIN_NEQ_SYMS) {
        fprintf(stderr, "[-] kallsyms find approximate kallsyms_offsets error\n");
        return -1;
    }
    cand -= KSYM_MIN_NEQ_SYMS * elem_size;
    for (;; cand -= elem_size)
        if (!int_unpack(img + cand, elem_size, info->is_be)) break;
    for (;; cand -= elem_size) {
        if (int_unpack(img + cand, elem_size, info->is_be)) break;
        if (zero_offset_num++ >= MAX_ZERO_OFFSET_NUM) break;
    }
    cand += elem_size;
    int32_t approx_offset = cand;
    info->_approx_addresses_or_offsets_offset = approx_offset;

    // approximate kallsyms_offsets end
    prev_offset = 0;
    for (; cand < imglen; cand += elem_size) {
        int64_t offset = int_unpack(img + cand, elem_size, info->is_be);
        if (offset < prev_offset) break;
        prev_offset = offset;
    }
    // the last symbol may not 4k alinged
    // end is not include
    int32_t end = cand;
    info->_approx_addresses_or_offsets_end = end;
    info->has_relative_base = 1;
    int32_t approx_num_syms = (end - approx_offset) / elem_size;
    info->_approx_addresses_or_offsets_num = approx_num_syms;
    // The real interval is contained in this approximate interval
    fprintf(stdout,
            "[+] kallsyms approximate kallsyms_offsets range: [0x%08x, 0x%08x) "
            "count: 0x%08x\n",
            approx_offset, end, approx_num_syms);
    return 0;
}

static int32_t find_approx_addresses_or_offset(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t ret = 0;
    if (info->version.major > 4 || (info->version.major == 4 && info->version.minor >= 6)) {
        // may have kallsyms_relative_base
        ret = find_approx_offsets(info, img, imglen);
        if (!ret) return 0;
    }
    ret = find_approx_addresses(info, img, imglen);
    return ret;
}

static int find_num_syms(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t approx_end = info->_approx_addresses_or_offsets_end;
    // int32_t num_syms_elem_size = get_num_syms_elem_size(info);
    int32_t num_syms_elem_size = 4;

    int32_t approx_num_syms = info->_approx_addresses_or_offsets_num;
    int32_t nsyms = 0;
    int32_t nsyms_max_offset = approx_end + 4096;
    int32_t NSYMS_MAX_GAP = 20;
    int32_t LAST_SYM_EQUAL_NUM = 10;
    int32_t cand = approx_end / num_syms_elem_size * num_syms_elem_size - LAST_SYM_EQUAL_NUM * num_syms_elem_size;

    for (; cand < nsyms_max_offset; cand += num_syms_elem_size) {
        nsyms = (int)int_unpack(img + cand, num_syms_elem_size, info->is_be);
        if (approx_num_syms >= nsyms && approx_num_syms - nsyms < NSYMS_MAX_GAP) break;
    }

    if (cand >= nsyms_max_offset) {
        fprintf(stderr, "[-] kallsyms kallsyms_num_syms error\n");
        return -1;
    } else {
        info->kallsyms_num_syms = nsyms;
        info->kallsyms_num_syms_offset = cand;
        fprintf(stdout, "[+] kallsyms kallsyms_num_syms offset: 0x%08x, value: 0x%08x\n", cand, nsyms);
    }
    return 0;
}

static int find_markers(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t elem_size = get_markers_elem_size(info);
    int32_t cand = info->kallsyms_token_table_offset - elem_size;
    int64_t marker;
    for (;; cand -= elem_size) {
        marker = int_unpack(img + cand, elem_size, info->is_be);
        if (marker) break;
    }
    int32_t marker_end = cand + elem_size;
    int64_t last_marker = 0x7fffffff;
    for (;; cand -= elem_size) {
        marker = int_unpack(img + cand, elem_size, info->is_be);
        if (!marker || last_marker <= marker) break;
        last_marker = marker;
    }
    int32_t marker_num = (marker_end - cand) / elem_size;
    if (marker || marker_num < KSYM_MIN_MARKER) {
        fprintf(stderr, "[-] kallsyms find kallsyms_markers error\n");
        return -1;
    }
    info->kallsyms_markers_offset = cand;
    info->_marker_num = marker_num;
    fprintf(stdout, "[+] kallsyms kallsyms_markers range: [0x%08x, 0x%08x), count: 0x%08x\n", cand, marker_end,
            marker_num);
    return 0;
}

static int decompress_symbol_name(kallsym_t *info, char *img, int32_t *pos_to_next, char *out_type, char *out_symbol)
{
    int32_t pos = *pos_to_next;
    int32_t len = *(uint8_t *)(img + pos++);
    if (len > 0x7F) len = (len & 0x7F) + (*(uint8_t *)(img + pos++) << 7);
    if (!len || len >= KSYM_SYMBOL_LEN) return -1;

    *pos_to_next = pos + len;
    for (int32_t i = 0; i < len; i++) {
        int32_t tokidx = *(uint8_t *)(img + pos + i);
        char *token = info->kallsyms_token_table[tokidx];
        if (!i) { // first character, symbol type
            if (out_type) *out_type = *token;
            token++;
        }
        if (out_symbol) strcat(out_symbol, token);
    }
    return 0;
}

static int is_symbol_name_pos(kallsym_t *info, char *img, int32_t pos, char *symbol)
{
    int32_t len = *(uint8_t *)(img + pos++);
    if (len > 0x7F) len = (len & 0x7F) + (*(uint8_t *)(img + pos++) << 7);
    if (!len || len >= KSYM_SYMBOL_LEN) return 0;
    int32_t symidx = 0;
    for (int32_t i = 0; i < len; i++) {
        int32_t tokidx = *(uint8_t *)(img + pos + i);
        char *token = info->kallsyms_token_table[tokidx];
        if (!i) token++; // ignore symbol type
        int32_t toklen = strlen(token);
        if (strncmp(symbol + symidx, token, toklen)) break;
        symidx += toklen;
    }
    return (int32_t)strlen(symbol) == symidx;
}

static int find_names(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t marker_elem_size = get_markers_elem_size(info);
    int32_t cand = info->_approx_addresses_or_offsets_offset;
    int32_t test_marker_num = -1;
    for (; cand < info->kallsyms_markers_offset; cand++) {
        int32_t pos = cand;
        test_marker_num = KSYM_FIND_NAMES_USED_MARKER; // check n * 256 symbols
        for (int32_t i = 0;; i++) {
            int32_t len = *(uint8_t *)(img + pos++);
            if (len > 0x7F) len = (len & 0x7F) + (*(uint8_t *)(img + pos++) << 7);
            if (!len || len >= KSYM_SYMBOL_LEN) break;
            pos += len;
            if (pos >= info->kallsyms_markers_offset) break;

            if (i && (i & 0xFF) == 0xFF) { // every 256 symbols
                int32_t mark_len = int_unpack(img + info->kallsyms_markers_offset + ((i >> 8) + 1) * marker_elem_size,
                                              marker_elem_size, info->is_be);
                if (pos - cand != mark_len) break;
                if (!--test_marker_num) break;
            }
        }
        if (!test_marker_num) break;
    }
    if (test_marker_num) {
        fprintf(stderr, "[-] kallsyms find kallsyms_names error\n");
        return -1;
    }
    info->kallsyms_names_offset = cand;
    fprintf(stdout, "[+] kallsyms kallsyms_names offset: 0x%08x\n", cand);
    return 0;
}

static int find_vectors(kallsym_t *info, char *img, int32_t imglen)
{
    // .align 11
    // todo
    return 0;
}

static int correct_addresses_or_offsets(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t pos = info->kallsyms_names_offset;
    int32_t index = 0;
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    // Pick a symbol (linux_banner) whose offset we know, use its index to fix the
    // beginning of the addresses or offsets table
    while (pos < info->kallsyms_markers_offset) {
        memset(symbol, 0, sizeof(symbol));
        int32_t ret = decompress_symbol_name(info, img, &pos, NULL, symbol);
        if (ret) break;
        if (!ret && !strcmp(symbol, "linux_banner")) {
            fprintf(stdout, "[+] kallsyms linux_banner index: 0x%08x\n", index);
            break;
        }
        index++;
    }

    info->symbol_banner_idx = -1;
    // find correct addresses or offsets
    for (int i = 0; i < info->banner_num; i++) {
        int32_t target_offset = info->linux_banner_offset[i];
        int32_t elem_size = info->has_relative_base ? get_offsets_elem_size(info) : get_addresses_elem_size(info);
        pos = info->_approx_addresses_or_offsets_offset;
        int32_t end = pos + 4096 + elem_size;
        for (; pos < end; pos += elem_size) {
            uint64_t first_elem_val = uint_unpack(img + pos, elem_size, info->is_be);
            int32_t offset = uint_unpack(img + pos + index * elem_size, elem_size, info->is_be) - first_elem_val;
            if (offset == target_offset) break;
        }
        if (pos < end) {
            info->symbol_banner_idx = i;
            break;
        }
    }
    if (info->symbol_banner_idx < 0) {
        fprintf(stderr, "[-] kallsyms correct addressed or offsets error\n");
        return -1;
    }

    if (info->has_relative_base) {
        info->kallsyms_offsets_offset = pos;
        fprintf(stdout, "[+] kallsyms kallsyms_offsets offset: 0x%08x\n", pos);
    } else {
        info->kallsyms_addresses_offset = pos;
        fprintf(stdout, "[+] kallsyms kallsyms_addresses offset: 0x%08x\n", pos);
    }
    return 0;
}

void init_arm64_kallsym_t(kallsym_t *info)
{
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = 1;
    info->asm_long_size = 4;
    info->asm_PTR_size = 8;
    info->try_relo = 1;
}

void init_not_tested_arch_kallsym_t(kallsym_t *info, int32_t is_64)
{
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = is_64;
    info->asm_long_size = 4;
    info->asm_PTR_size = 4;
    info->try_relo = 0;
    if (is_64) info->asm_PTR_size = 8;
}

/*
R kallsyms_offsets
R kallsyms_relative_base
R kallsyms_num_syms
R kallsyms_names
R kallsyms_markers
R kallsyms_token_table
R kallsyms_token_index
*/
int analyze_kallsym_info(kallsym_t *info, char *img, int32_t imglen, enum arch_type arch, int32_t is_64)
{
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = is_64;
    info->asm_long_size = 4;
    info->asm_PTR_size = 4;
    if (arch == ARM64) info->try_relo = 1;
    if (is_64) info->asm_PTR_size = 8;

    info->img_offset = 0;
    if (!strncmp("UNCOMPRESSED_IMG", img, strlen("UNCOMPRESSED_IMG"))) {
        info->img_offset = 0x14;
    }
    img += info->img_offset;
    imglen -= info->img_offset;

    int32_t (*funcs[])(kallsym_t *, char *, int32_t) = { find_linux_banner,
                                                         find_token_table,
                                                         find_token_index,
                                                         try_find_arm64_relo_table,
                                                         find_markers,
                                                         find_approx_addresses_or_offset,
                                                         find_names,
                                                         find_num_syms,
                                                         correct_addresses_or_offsets };
    for (int i = 0; i < (int)(sizeof(funcs) / sizeof(funcs[0])); i++) {
        if (funcs[i](info, img, imglen)) return -1;
    }
    return 0;
}

int32_t get_symbol_index_offset(kallsym_t *info, char *img, int32_t index)
{
    img = img + info->img_offset;

    int32_t elem_size;
    int32_t pos;
    if (info->has_relative_base) {
        elem_size = get_offsets_elem_size(info);
        pos = info->kallsyms_offsets_offset;
    } else {
        elem_size = get_addresses_elem_size(info);
        pos = info->kallsyms_addresses_offset;
    }
    uint64_t first = uint_unpack(img + pos, elem_size, info->is_be);
    uint64_t target = uint_unpack(img + pos + index * elem_size, elem_size, info->is_be);
    return (int32_t)(target - first);
}

int32_t get_symbol_offset(kallsym_t *info, char *img, char *symbol)
{
    img = img + info->img_offset;

    char decomp[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(decomp, 0, sizeof(decomp));
        decompress_symbol_name(info, img, &pos, &type, decomp);
        if (!strcmp(decomp, symbol)) {
            int32_t offset = get_symbol_index_offset(info, img, i);
            fprintf(stdout, "[+] kallsyms %s: type: %c, offset: 0x%08x\n", symbol, type, offset);
            return offset;
        }
    }
    fprintf(stderr, "[-] kallsyms can't find symbol: %s\n", symbol);
    return -1;
}

int dump_all_symbols(kallsym_t *info, char *img)
{
    img = img + info->img_offset;

    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(symbol, 0, sizeof(symbol));
        decompress_symbol_name(info, img, &pos, &type, symbol);
        int32_t offset = get_symbol_index_offset(info, img, i);
        printf("0x%08x %c %s\n", offset, type, symbol);
    }
    return 0;
}

int on_each_symbol(kallsym_t *info, char *img, void *userdata,
                   int32_t (*fn)(int32_t index, char *type, const char *symbol, int32_t offset, void *userdata))
{
    img = img + info->img_offset;

    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(symbol, 0, sizeof(symbol));
        decompress_symbol_name(info, img, &pos, &type, symbol);
        int32_t offset = get_symbol_index_offset(info, img, i);
        if (fn(i, &type, symbol, offset, userdata)) return -1;
    }
    return 0;
}
