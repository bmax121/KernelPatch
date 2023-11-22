#ifndef _KP_RELO_H_
#define _KP_RELO_H_

#include <uapi/linux/elf.h>

int apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                       struct module *me);
int apply_relocate(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                   struct module *me);

#endif