#ifndef _KP_SYMBOL_H_
#define _KP_SYMBOL_H_

#define KP_SYMBOL_LEN 31

// todo: name len
typedef struct
{
    const char name[KP_SYMBOL_LEN + 1];
    unsigned long addr;
    unsigned long hash;
} kp_symbol_t;

#define _KP_EXPORT_SYMBOL(sym)                                 \
    static kp_symbol_t __kp_symbol_##sym __attribute__((used)) \
    __attribute__((section(".kp.symbol"))) = { .name = #sym, .addr = (unsigned long)&sym, .hash = 0 }

#define KP_EXPORT_SYMBOL(sym) _KP_EXPORT_SYMBOL(sym)

unsigned long symbol_lookup_name(const char *name);

int symbol_init();

#endif