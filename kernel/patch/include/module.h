#ifndef _KP_MODULE_H_
#define _KP_MODULE_H_

#include <asm-generic/module.h>
#include <kpmodule.h>

struct load_info
{
    struct
    {
        const char *base;
        unsigned long size;
        const char *name, *version, *license, *author, *description;
    } info;
    Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings, *strtab;
    unsigned long symoffs, stroffs;
    struct
    {
        unsigned int sym, str, mod, info;
    } index;
};

struct module
{
    struct
    {
        const char *base, *name, *version, *license, *author, *description;
    } info;

    char *args;
    initcall_t *init;
    exitcall_t *exit;

    unsigned int size;
    unsigned int text_size;
    unsigned int ro_size;

    void *start;

    struct list_head list;
};

int load_module(void *data, int len, const char *args);
int load_module_path(const char *path, const char *args);
int unload_module(const char *name);
struct module *find_module(const char *name);

int get_module_nums();
int list_modules(char *out_names, int size);
int get_module_info(const char *name, char *out_info, int size);

int module_init();

#endif