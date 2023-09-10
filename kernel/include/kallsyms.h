#ifndef _KP_KALLSYMS_H_
#define _KP_KALLSYMS_H_

struct module;

#define KSYM_NAME_LEN 512

extern int (*kallsyms_on_each_symbol)(int (*fn)(void *, const char *, struct module *, unsigned long), void *data);
extern unsigned long (*kallsyms_lookup_name)(const char *name);
extern int (*lookup_symbol_attrs)(unsigned long addr, unsigned long *size, unsigned long *offset, char *modname,
                                  char *name);

#endif