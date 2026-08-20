/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <preset.h>
#include <stdint.h>

extern setup_header_t x86_header;
extern setup_preset_t x86_setup_preset;

#define X86_SERIAL_PORT 0x3f8
#define X86_KP_MAGIC_U64 0x000038353131504bull

static inline setup_header_t *x86_get_header(void)
{
    setup_header_t *header;
    __asm__("leaq x86_header(%%rip), %0" : "=r"(header));
    return header;
}

static inline setup_preset_t *x86_get_setup_preset(void)
{
    setup_preset_t *preset;
    __asm__("leaq x86_setup_preset(%%rip), %0" : "=r"(preset));
    return preset;
}

static inline void x86_serial_putc(char c)
{
    __asm__ volatile("outb %b0, %w1" : : "a"(c), "Nd"(X86_SERIAL_PORT));
}

static void x86_serial_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') x86_serial_putc('\r');
        x86_serial_putc(*s++);
    }
}

static void x86_serial_hex_byte(uint8_t value)
{
    static const char digits[] = "0123456789abcdef";

    x86_serial_putc(digits[value >> 4]);
    x86_serial_putc(digits[value & 0xf]);
}

void kpimg_x86_start(void)
{
    setup_header_t *header = x86_get_header();
    setup_preset_t *preset = x86_get_setup_preset();

    x86_serial_puts("KP x86: bootstrap\n");
    if (*(const uint64_t *)header->magic != X86_KP_MAGIC_U64 ||
        !(header->config_flags & CONFIG_FLAG_X86_64))
        goto bad;
    if (preset->setup_offset < 0 || preset->kernel_size <= 0 ||
        preset->start_offset < 0 || !preset->kallsyms_lookup_name_offset ||
        (!*(const uint64_t *)preset->root_superkey && !*(const uint64_t *)preset->superkey))
        goto bad;

    x86_serial_puts("KP x86: kernel(hex) ");
    x86_serial_hex_byte(preset->kernel_version.major);
    x86_serial_putc('.');
    x86_serial_hex_byte(preset->kernel_version.minor);
    x86_serial_putc('.');
    x86_serial_hex_byte(preset->kernel_version.patch);
    x86_serial_puts(" preset/key ready\n");
    return;

bad:
    x86_serial_puts("KP x86: bad preset\n");
}
