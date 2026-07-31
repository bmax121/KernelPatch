/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _GNU_SOURCE
#include "x86_64.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "common.h"
#include "elf/elf.h"
#include "kallsym.h"
#include "preset.h"

#define X86_BOOT_FLAG_OFFSET 0x1fe
#define X86_SETUP_SECTS_OFFSET 0x1f1
#define X86_HEADER_MAGIC_OFFSET 0x202
#define X86_PAYLOAD_OFFSET_OFFSET 0x248
#define X86_PAYLOAD_LENGTH_OFFSET 0x24c
#define X86_SYSSIZE_OFFSET 0x1f4

/* Five-byte ftrace NOP at start_kernel, replaced by a call rel32. */
#define CALL_PATCH_SIZE 5
#define TRAMPOLINE_SIZE 16

static uint16_t get_le16(const void *ptr)
{
    const uint8_t *p = ptr;
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

static uint32_t get_le32(const void *ptr)
{
    const uint8_t *p = ptr;
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void put_le32(void *ptr, uint32_t value)
{
    uint8_t *p = ptr;
    p[0] = value;
    p[1] = value >> 8;
    p[2] = value >> 16;
    p[3] = value >> 24;
}

static int put_rel32(uint8_t *dst, uint8_t opcode, uint64_t source, uint64_t target)
{
    int64_t displacement = (int64_t)target - (int64_t)(source + 5);
    if (displacement < INT32_MIN || displacement > INT32_MAX) return -1;
    dst[0] = opcode;
    put_le32(dst + 1, (uint32_t)(int32_t)displacement);
    return 0;
}

bool is_x86_bzimage(const void *data, size_t size)
{
    const uint8_t *p = data;
    return size > X86_PAYLOAD_LENGTH_OFFSET + 4 && get_le16(p + X86_BOOT_FLAG_OFFSET) == 0xaa55 &&
           !memcmp(p + X86_HEADER_MAGIC_OFFSET, "HdrS", 4);
}

static int gzip_decompress(const uint8_t *src, size_t src_size, char **out, size_t *out_size)
{
    if (src_size < 4) return -1;

    z_stream stream = { 0 };
    if (inflateInit2(&stream, 15 + 16) != Z_OK) return -1;

    /* The gzip ISIZE trailer is unusable here: gzip_pad_to_size() appends zeros
       after the stream, so a repacked image has no valid ISIZE at src_size - 4.
       Grow the output buffer instead until inflate reports the end of stream. */
    size_t capacity = src_size * 4;
    if (capacity < (1u << 20)) capacity = 1u << 20;
    char *buffer = malloc(capacity);
    if (!buffer) {
        inflateEnd(&stream);
        return -1;
    }

    stream.next_in = (Bytef *)src;
    stream.avail_in = src_size > UINT_MAX ? UINT_MAX : (uInt)src_size;

    for (;;) {
        if (stream.total_out == capacity) {
            if (capacity > SIZE_MAX / 2) goto error;
            char *grown = realloc(buffer, capacity * 2);
            if (!grown) goto error;
            buffer = grown;
            capacity *= 2;
        }
        stream.next_out = (Bytef *)buffer + stream.total_out;
        size_t room = capacity - stream.total_out;
        stream.avail_out = room > UINT_MAX ? UINT_MAX : (uInt)room;

        int rc = inflate(&stream, Z_NO_FLUSH);
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK) {
            tools_loge("decompress x86 payload failed: %d\n", rc);
            goto error;
        }
        /* Z_OK with output room left means inflate ran out of input first. */
        if (stream.avail_out) {
            tools_loge("decompress x86 payload failed: truncated gzip stream\n");
            goto error;
        }
    }

    *out_size = stream.total_out;
    char *shrunk = realloc(buffer, stream.total_out ? stream.total_out : 1);
    *out = shrunk ? shrunk : buffer;
    inflateEnd(&stream);
    return 0;

error:
    free(buffer);
    inflateEnd(&stream);
    return -1;
}

/* /tmp does not exist on Android, where kptools normally runs. */
static void temp_template(char *buf, size_t buf_size, const char *tag)
{
    const char *dir = getenv("TMPDIR");
    if (!dir || !*dir) dir = getenv("TMP");
    if (!dir || !*dir) dir = getenv("TEMP");
    if (!dir || !*dir) dir = ".";
    snprintf(buf, buf_size, "%s/kptools-%s-XXXXXX", dir, tag);
}

static int gzip_compress(const uint8_t *src, size_t src_size, char **out, size_t *out_size)
{
    /* Pipe through system gzip -9 -n because this WSA kernel's inflate
       rejects deflate streams from any other compressor (including zlib). */
    char tmp_in[512];
    char tmp_out[512];
    temp_template(tmp_in, sizeof(tmp_in), "gzin");
    temp_template(tmp_out, sizeof(tmp_out), "gzout");

    {
        int fd = mkstemp(tmp_in);
        if (fd < 0) {
            tools_loge("cannot create a temporary file at %s, set TMPDIR to a writable directory\n", tmp_in);
            return -1;
        }
        FILE *fin = fdopen(fd, "wb");
        if (!fin) { close(fd); unlink(tmp_in); return -1; }
        if (fwrite(src, 1, src_size, fin) != src_size) {
            tools_loge("cannot write the temporary file %s\n", tmp_in);
            fclose(fin);
            unlink(tmp_in);
            return -1;
        }
        fclose(fin);
    }

    {
        int fd = mkstemp(tmp_out);
        if (fd < 0) {
            tools_loge("cannot create a temporary file at %s, set TMPDIR to a writable directory\n", tmp_out);
            unlink(tmp_in);
            return -1;
        }
        close(fd);
    }

    char cmd[1152];
    snprintf(cmd, sizeof(cmd), "gzip -9 -n -c '%s' > '%s'", tmp_in, tmp_out);
    int rc = system(cmd);
    unlink(tmp_in);
    if (rc != 0) {
        tools_loge("gzip -9 -n failed (rc=%d); the external gzip binary is required to repack a bzImage\n", rc);
        unlink(tmp_out);
        return -1;
    }

    int file_len = 0;
    char *buf = NULL;
    read_file(tmp_out, &buf, &file_len);
    unlink(tmp_out);
    if (!buf || file_len <= 0) {
        tools_loge("gzip produced no output\n");
        free(buf);
        return -1;
    }

    *out = buf;
    *out_size = (size_t)file_len;
    return 0;
}

/* In-process gzip, so a repack needs neither a temporary directory nor an
   external binary.  On the kernels tested this also packs a few KiB tighter
   than GNU gzip -9, which is often the difference between fitting the fixed
   payload slot and not. */
static int zlib_gzip_compress(const uint8_t *src, size_t src_size, char **out, size_t *out_size)
{
    z_stream stream = { 0 };
    if (deflateInit2(&stream, 9, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return -1;

    size_t capacity = deflateBound(&stream, src_size);
    char *buffer = malloc(capacity);
    if (!buffer) {
        deflateEnd(&stream);
        return -1;
    }

    stream.next_in = (Bytef *)src;
    stream.next_out = (Bytef *)buffer;
    int rc = Z_OK;
    size_t consumed = 0;
    for (;;) {
        if (!stream.avail_in && consumed < src_size) {
            size_t chunk = src_size - consumed;
            stream.avail_in = chunk > UINT_MAX ? UINT_MAX : (uInt)chunk;
            consumed += stream.avail_in;
        }
        if (!stream.avail_out) {
            size_t room = capacity - stream.total_out;
            stream.avail_out = room > UINT_MAX ? UINT_MAX : (uInt)room;
            if (!stream.avail_out) break; /* deflateBound was wrong */
        }
        rc = deflate(&stream, consumed < src_size ? Z_NO_FLUSH : Z_FINISH);
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK) break;
    }
    if (rc != Z_STREAM_END) {
        tools_loge("zlib deflate failed: %d\n", rc);
        free(buffer);
        deflateEnd(&stream);
        return -1;
    }

    *out_size = stream.total_out;
    *out = buffer;
    deflateEnd(&stream);
    return 0;
}

static int gzip_pad_to_size(char **payload, size_t *payload_size, size_t target_size)
{
    if (*payload_size > target_size) return -1;
    size_t padding = target_size - *payload_size;
    if (!padding) return 0;

    char *padded = malloc(target_size);
    if (!padded) return -1;

    /* The WSA decompressor accepts bytes after a completed gzip stream but
       rejects optional gzip header fields. Keep the original header intact. */
    memcpy(padded, *payload, *payload_size);
    memset(padded + *payload_size, 0, padding);

    free(*payload);
    *payload = padded;
    *payload_size = target_size;
    return 0;
}

static int map_elf_load_segments(x86_bzimage_t *image)
{
    if (image->elf_size < sizeof(Elf64_Ehdr)) return -1;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image->elf;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) || ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB || ehdr->e_machine != EM_X86_64 || ehdr->e_phentsize != sizeof(Elf64_Phdr))
        return -1;
    if (ehdr->e_phoff > image->elf_size || (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr) > image->elf_size - ehdr->e_phoff)
        return -1;

    Elf64_Phdr *phdr = (Elf64_Phdr *)(image->elf + ehdr->e_phoff);
    uint64_t phys_base = UINT64_MAX;
    uint64_t phys_end = 0;
    uint64_t virt_base = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD || !phdr[i].p_filesz) continue;
        if (phdr[i].p_offset > image->elf_size || phdr[i].p_filesz > image->elf_size - phdr[i].p_offset) return -1;
        if (phdr[i].p_paddr < phys_base) {
            phys_base = phdr[i].p_paddr;
            virt_base = phdr[i].p_vaddr;
        }
        /* p_filesz may exceed p_memsz in a malformed image, and the copy loop
           below writes p_filesz bytes, so the span must cover both. */
        uint64_t span = phdr[i].p_memsz > phdr[i].p_filesz ? phdr[i].p_memsz : phdr[i].p_filesz;
        if (phdr[i].p_paddr + span > phys_end) phys_end = phdr[i].p_paddr + span;
    }
    if (phys_base == UINT64_MAX || phys_end <= phys_base || phys_end - phys_base > INT_MAX) return -1;

    image->flat_size = phys_end - phys_base;
    image->flat = calloc(1, image->flat_size);
    if (!image->flat) return -1;
    image->phys_base = phys_base;
    image->virt_base = virt_base;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD || !phdr[i].p_filesz) continue;
        uint64_t flat_offset = phdr[i].p_paddr - phys_base;
        if (flat_offset > image->flat_size || phdr[i].p_filesz > image->flat_size - flat_offset) return -1;
        memcpy(image->flat + flat_offset, image->elf + phdr[i].p_offset, phdr[i].p_filesz);
    }

    tools_logi("x86 bzImage payload: 0x%zx+0x%zx, ELF: 0x%zx, flat: 0x%zx, phys: 0x%llx, virt: 0x%llx\n",
               image->payload_start, image->payload_size, image->elf_size, image->flat_size,
               (unsigned long long)image->phys_base, (unsigned long long)image->virt_base);
    return 0;
}

int load_x86_bzimage(const char *path, x86_bzimage_t *image)
{
    memset(image, 0, sizeof(*image));

    int file_size = 0;
    read_file(path, &image->bzimage, &file_size);
    image->bzimage_size = file_size;
    if (!is_x86_bzimage(image->bzimage, image->bzimage_size)) goto error;

    uint8_t setup_sects = (uint8_t)image->bzimage[X86_SETUP_SECTS_OFFSET];
    if (!setup_sects) setup_sects = 4;
    size_t protected_start = ((size_t)setup_sects + 1) * 512;
    uint32_t payload_offset = get_le32(image->bzimage + X86_PAYLOAD_OFFSET_OFFSET);
    uint32_t payload_length = get_le32(image->bzimage + X86_PAYLOAD_LENGTH_OFFSET);
    image->payload_start = protected_start + payload_offset;
    image->payload_size = payload_length;
    if (image->payload_start > image->bzimage_size || image->payload_size > image->bzimage_size - image->payload_start)
        goto error;

    if (gzip_decompress((uint8_t *)image->bzimage + image->payload_start, image->payload_size, &image->elf,
                        &image->elf_size))
        goto error;
    if (map_elf_load_segments(image)) goto error;
    return 0;

error:
    free_x86_bzimage(image);
    return -1;
}

int sync_x86_flat_to_elf(x86_bzimage_t *image)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image->elf;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(image->elf + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD || !phdr[i].p_filesz) continue;
        if (phdr[i].p_paddr < image->phys_base || phdr[i].p_paddr - image->phys_base > image->flat_size ||
            phdr[i].p_filesz > image->flat_size - (phdr[i].p_paddr - image->phys_base))
            return -1;
        if (phdr[i].p_offset > image->elf_size || phdr[i].p_filesz > image->elf_size - phdr[i].p_offset) return -1;
        memcpy(image->elf + phdr[i].p_offset, image->flat + phdr[i].p_paddr - image->phys_base, phdr[i].p_filesz);
    }
    return 0;
}

/* Kernel virtual address of a flat-image offset.  The vaddr-paddr delta is
   per-segment, so it cannot be derived from virt_base alone. */
static int flat_offset_to_va(const x86_bzimage_t *image, uint64_t flat_offset, uint64_t *va)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image->elf;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(image->elf + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD || !phdr[i].p_memsz || phdr[i].p_paddr < image->phys_base) continue;
        uint64_t segment_offset = phdr[i].p_paddr - image->phys_base;
        if (flat_offset < segment_offset || flat_offset - segment_offset >= phdr[i].p_memsz) continue;
        *va = phdr[i].p_vaddr + (flat_offset - segment_offset);
        return 0;
    }
    return -1;
}

static bool flat_range_ok(const x86_bzimage_t *image, uint64_t offset, uint64_t size)
{
    return offset <= image->flat_size && size <= image->flat_size - offset;
}

int inject_x86_kpimg(x86_bzimage_t *image, void *kpimg, size_t kpimg_size)
{
    static const uint8_t ftrace_nop[CALL_PATCH_SIZE] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };

    if (kpimg_size <= KP_X86_ENTRY_OFFSET || kpimg_size < sizeof(preset_t)) return -1;
    preset_t *preset = kpimg;
    char magic[MAGIC_LEN] = KP_MAGIC;
    if (memcmp(preset->header.magic, magic, MAGIC_LEN) ||
        !(preset->header.config_flags & CONFIG_FLAG_X86_64))
        return -1;

    /* The whole kpimg goes in, preset included: the runtime addresses its own
       setup_preset_t relative to the blob base, and unpatch locates the blob by
       scanning for the preset magic. */
    size_t runtime_size = kpimg_size;

    kallsym_t kallsym;
    if (analyze_kallsym_info(&kallsym, image->flat, image->flat_size, X86_64, 1)) {
        tools_loge("cannot resolve x86 start_kernel\n");
        return -1;
    }
    int32_t start_kernel_offset = get_symbol_offset(&kallsym, image->flat, "start_kernel");
    /* HDR_BACKUP_SIZE, not CALL_PATCH_SIZE: unpatch restores the full backup. */
    if (start_kernel_offset < 0 || !flat_range_ok(image, (uint64_t)start_kernel_offset, HDR_BACKUP_SIZE)) {
        tools_loge("x86 start_kernel is unavailable\n");
        return -1;
    }

    uint8_t *call_site = (uint8_t *)image->flat + start_kernel_offset;
    if (memcmp(call_site, ftrace_nop, sizeof(ftrace_nop))) {
        tools_loge("unsupported x86 start_kernel prologue; expected five-byte ftrace NOP\n");
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image->elf;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(image->elf + ehdr->e_phoff);
    Elf64_Phdr *payload_segment = NULL;
    int payload_segment_index = -1;
    uint64_t payload_segment_offset = 0;
    uint64_t kpimg_segment_offset = 0;
    uint64_t payload_run_size = UINT64_MAX;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD || !(phdr[i].p_flags & PF_X)) continue;
        uint64_t segment_flat_offset = phdr[i].p_paddr - image->phys_base;
        if (segment_flat_offset > image->flat_size || phdr[i].p_filesz > image->flat_size - segment_flat_offset)
            continue;

        uint8_t *segment = (uint8_t *)image->flat + segment_flat_offset;
        uint64_t run_start = 0;
        for (uint64_t pos = 0; pos < phdr[i].p_filesz; pos++) {
            if (!segment[pos]) {
                if (pos == 0 || segment[pos - 1]) run_start = pos;
                uint64_t payload_offset = (run_start + 15) & ~15ull;
                uint64_t trampoline_offset = (payload_offset + runtime_size + 15) & ~15ull;
                if (trampoline_offset > pos || TRAMPOLINE_SIZE > pos - trampoline_offset + 1) continue;
                if (pos - run_start + 1 >= payload_run_size) continue;
                payload_segment = &phdr[i];
                payload_segment_index = i;
                kpimg_segment_offset = payload_offset;
                payload_segment_offset = trampoline_offset;
                payload_run_size = pos - run_start + 1;
            }
        }
    }
    if (!payload_segment) {
        tools_loge("x86 executable segment has no room for kpimg\n");
        return -1;
    }

    uint64_t trampoline_phys = payload_segment->p_paddr + payload_segment_offset;
    uint64_t trampoline_flat_offset = trampoline_phys - image->phys_base;
    if (!flat_range_ok(image, trampoline_flat_offset, TRAMPOLINE_SIZE)) return -1;
    uint64_t payload_phys = payload_segment->p_paddr + kpimg_segment_offset;
    uint64_t payload_flat_offset = payload_phys - image->phys_base;
    if (!flat_range_ok(image, payload_flat_offset, runtime_size)) return -1;

    uint64_t call_site_va = 0;
    uint64_t trampoline_va = 0;
    uint64_t payload_entry = 0;
    if (flat_offset_to_va(image, (uint64_t)start_kernel_offset, &call_site_va) ||
        flat_offset_to_va(image, trampoline_flat_offset, &trampoline_va) ||
        flat_offset_to_va(image, payload_flat_offset + KP_X86_ENTRY_OFFSET, &payload_entry)) {
        tools_loge("cannot map an x86 flat offset back to a kernel virtual address\n");
        return -1;
    }

    /* x86 use of the shared preset fields; remove_x86_kpimg() reads them back:
         setup_offset       flat offset of the injected blob (and of this preset)
         kpimg_size         injected blob size
         paging_init_offset flat offset of the 16-byte trampoline
         map_offset         flat offset of the patched start_kernel call site   */
    setup_preset_t *setup = &preset->setup;
    setup->kimg_size = payload_segment->p_filesz;
    setup->kpimg_size = kpimg_size;
    setup->kernel_size = payload_segment->p_memsz;
    setup->page_shift = 12;
    setup->setup_offset = payload_flat_offset;
    setup->start_offset = start_kernel_offset;
    setup->extra_size = image->payload_size;
    setup->map_offset = start_kernel_offset;
    setup->map_max_size = payload_segment_index;
    setup->paging_init_offset = trampoline_flat_offset;
    memcpy(setup->header_backup, call_site, HDR_BACKUP_SIZE);

    uint8_t *trampoline = (uint8_t *)image->flat + trampoline_flat_offset;
    trampoline[0] = 0x50; /* push rax */
    trampoline[1] = 0x48;
    trampoline[2] = 0xb8; /* movabs rax, in-kernel kpimg entry */
    for (int i = 0; i < 8; i++) trampoline[3 + i] = (uint8_t)(payload_entry >> (8 * i));
    trampoline[11] = 0xff;
    trampoline[12] = 0xd0; /* call rax */
    trampoline[13] = 0x58; /* pop rax */
    trampoline[14] = 0xc3; /* ret */
    trampoline[15] = 0x90;
    if (put_rel32(call_site, 0xe8, call_site_va, trampoline_va)) return -1;

    /* Written last so that every setup_preset_t field above lands in the image. */
    memcpy(image->flat + payload_flat_offset, kpimg, runtime_size);

    tools_logi("x86 kpimg injected: segment %d, start_kernel 0x%llx, trampoline 0x%llx, payload 0x%llx+0x%zx, "
               "entry 0x%llx\n",
               payload_segment_index, (unsigned long long)call_site_va, (unsigned long long)trampoline_phys,
               (unsigned long long)payload_phys, runtime_size, (unsigned long long)payload_entry);
    return 0;
}

int remove_x86_kpimg(x86_bzimage_t *image)
{
    char magic[MAGIC_LEN] = KP_MAGIC;
    preset_t *preset = NULL;
    size_t preset_offset = 0;
    for (size_t offset = 0; offset + sizeof(preset_t) <= image->flat_size; offset++) {
        if (memcmp(image->flat + offset, magic, MAGIC_LEN)) continue;
        preset_t *candidate = (preset_t *)(image->flat + offset);
        if (!(candidate->header.config_flags & CONFIG_FLAG_X86_64)) continue;
        if ((uint64_t)candidate->setup.setup_offset != offset) continue;
        preset = candidate;
        preset_offset = offset;
        break;
    }
    if (!preset) {
        tools_loge("x86 kpimg preset not found\n");
        return -1;
    }

    uint64_t blob_size = (uint64_t)preset->setup.kpimg_size;
    uint64_t trampoline_offset = (uint64_t)preset->setup.paging_init_offset;
    uint64_t entry_offset = (uint64_t)preset->setup.map_offset;
    uint64_t payload_slot_size = (uint64_t)preset->setup.extra_size;
    if (preset->setup.kpimg_size <= 0 || preset->setup.paging_init_offset < 0 || preset->setup.map_offset < 0 ||
        !flat_range_ok(image, preset_offset, blob_size) ||
        !flat_range_ok(image, trampoline_offset, TRAMPOLINE_SIZE) ||
        !flat_range_ok(image, entry_offset, HDR_BACKUP_SIZE)) {
        tools_loge("x86 kpimg preset describes an out-of-range region\n");
        return -1;
    }

    /* Injection writes into an existing zero run and never resizes a segment, so
       undoing it means restoring the call site and zeroing what was written.
       write_x86_bzimage() syncs flat back into the ELF afterwards. */
    uint8_t header_backup[HDR_BACKUP_SIZE];
    memcpy(header_backup, preset->setup.header_backup, HDR_BACKUP_SIZE);
    memset(image->flat + preset_offset, 0, blob_size);
    memset(image->flat + trampoline_offset, 0, TRAMPOLINE_SIZE);
    memcpy(image->flat + entry_offset, header_backup, HDR_BACKUP_SIZE);
    preset = NULL; /* just erased */

    if (payload_slot_size && image->payload_start + payload_slot_size <= image->bzimage_size)
        image->payload_size = payload_slot_size;

    tools_logi("x86 kpimg removed: blob 0x%zx+0x%llx, trampoline 0x%llx, restored call site 0x%llx\n", preset_offset,
               (unsigned long long)blob_size, (unsigned long long)trampoline_offset,
               (unsigned long long)(image->phys_base + entry_offset));
    return 0;
}

int write_x86_bzimage(x86_bzimage_t *image, const char *path)
{
    if (sync_x86_flat_to_elf(image)) return -1;

    /* The payload slot cannot grow: in a bzImage the compressed kernel sits
       inside the decompressor stub, with only a handful of spare bytes behind
       it.  GNU gzip -9 reproduces the vendor payload byte for byte, so try it
       first and fall back to zlib, which usually packs tighter, when the
       injected image no longer fits. */
    char *payload = 0;
    size_t payload_size = 0;
    const char *backend = "gzip -9";
    if (gzip_compress((uint8_t *)image->elf, image->elf_size, &payload, &payload_size)) {
        payload = 0;
        payload_size = 0;
    }
    tools_logi("x86 payload compressed with %s: 0x%zx (slot 0x%zx)\n", backend, payload_size, image->payload_size);
    if (!payload || payload_size > image->payload_size) {
        size_t gzip_size = payload_size;
        free(payload);
        payload = 0;
        payload_size = 0;
        backend = "zlib";
        if (zlib_gzip_compress((uint8_t *)image->elf, image->elf_size, &payload, &payload_size)) return -1;
        tools_logi("x86 payload compressed with %s: 0x%zx (slot 0x%zx)\n", backend, payload_size,
                   image->payload_size);
        if (payload_size > image->payload_size) {
            tools_loge("x86 payload does not fit the fixed bzImage slot: gzip 0x%zx, zlib 0x%zx, slot 0x%zx\n",
                       gzip_size, payload_size, image->payload_size);
            free(payload);
            return -1;
        }
        tools_logw("x86 payload was packed with zlib rather than GNU gzip; verify that this kernel boots\n");
    }
    if (gzip_pad_to_size(&payload, &payload_size, image->payload_size)) {
        free(payload);
        return -1;
    }

    size_t suffix_start = image->payload_start + image->payload_size;
    size_t suffix_size = image->bzimage_size - suffix_start;
    if (payload_size > UINT32_MAX || suffix_size < sizeof(uint32_t)) {
        free(payload);
        return -1;
    }

    size_t suffix_data_size = suffix_size - sizeof(uint32_t);
    size_t suffix_padding = image->suffix_payload_size ? (16 - (suffix_data_size & 15)) & 15 : 0;
    size_t output_size = image->payload_start + payload_size + suffix_data_size + suffix_padding +
                         image->suffix_payload_size + sizeof(uint32_t);
    uint32_t new_payload_len = (uint32_t)payload_size;
    char *output = malloc(output_size);
    if (!output) {
        free(payload);
        return -1;
    }

    memcpy(output, image->bzimage, image->payload_start);
    memcpy(output + image->payload_start, payload, payload_size);
    memcpy(output + image->payload_start + new_payload_len, image->bzimage + suffix_start, suffix_data_size);
    if (image->suffix_payload_size) {
        size_t payload_offset = image->payload_start + new_payload_len + suffix_data_size + suffix_padding;
        memset(output + image->payload_start + new_payload_len + suffix_data_size, 0, suffix_padding);
        memcpy(output + payload_offset, image->suffix_payload, image->suffix_payload_size);
    }
    put_le32(output + X86_PAYLOAD_LENGTH_OFFSET, new_payload_len);

    /* syssize: paragraphs (16-byte units) from setup end to image end */
    uint8_t setup_sects = (uint8_t)output[X86_SETUP_SECTS_OFFSET];
    if (!setup_sects) setup_sects = 4;
    size_t prot_size = output_size - ((size_t)setup_sects + 1) * 512;
    put_le32(output + X86_SYSSIZE_OFFSET, (prot_size + 15) / 16);

    /* x86 boot images store the complemented CRC32 in their final word. */
    put_le32(output + output_size - sizeof(uint32_t), ~crc32(0, (Bytef *)output, output_size - sizeof(uint32_t)));

    write_file(path, output, output_size, false);
    tools_logi("x86 bzImage repacked: payload 0x%zx -> 0x%zx, image 0x%zx -> 0x%zx\n", image->payload_size,
               payload_size, image->bzimage_size, output_size);
    free(output);
    free(payload);
    return 0;
}

void free_x86_bzimage(x86_bzimage_t *image)
{
    free(image->suffix_payload);
    free(image->flat);
    free(image->elf);
    free(image->bzimage);
    memset(image, 0, sizeof(*image));
}
