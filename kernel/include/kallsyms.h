#ifndef _KP_KALLSYMS_H_
#define _KP_KALLSYMS_H_

struct module;

#define KSYM_NAME_LEN 512

extern int (*kallsyms_on_each_symbol)(int (*fn)(void *, const char *, struct module *, unsigned long), void *data);
/* Lookup the address for a symbol. Returns 0 if not found. */
extern unsigned long (*kallsyms_lookup_name)(const char *name);
extern int (*kallsyms_lookup_size_offset)(unsigned long addr, unsigned long *symbolsize, unsigned long *offset);
/* Lookup an address.  modname is set to NULL if it's in the kernel. */
extern const char *(*kallsyms_lookup)(unsigned long addr, unsigned long *symbolsize, unsigned long *offset,
                                      char **modname, char *namebuf);
/* Look up a kernel symbol and return it in a text buffer. */
extern int (*sprint_symbol)(char *buffer, unsigned long address);
extern int (*sprint_symbol_no_offset)(char *buffer, unsigned long address);
extern int (*sprint_backtrace)(char *buffer, unsigned long address);

extern int (*lookup_symbol_name)(unsigned long addr, char *symname);
extern int (*lookup_symbol_attrs)(unsigned long addr, unsigned long *size, unsigned long *offset, char *modname,
                                  char *name);

// extern int sprint_symbol_build_id(char *buffer, unsigned long address);
// extern int sprint_backtrace_build_id(char *buffer, unsigned long address);

#endif