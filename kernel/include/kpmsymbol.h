/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_KPM_SYMBOL_RESOLVE_H_
#define _KP_KPM_SYMBOL_RESOLVE_H_

/* Resolver callbacks are supplied by kpimg or LKM. A pointer slot is not code. */
#define KPM_SYMBOL_DIRECT 1U
#define KPM_SYMBOL_FUNCTION_POINTER 2U
#define KPM_SYMBOL_DATA_POINTER 3U

struct kpm_symbol_resolution {
    unsigned long address;
    unsigned long target;
    unsigned int kind;
};

typedef unsigned long (*kpm_symbol_lookup_fn)(const char *name, void *context);
typedef unsigned long (*kpm_symbol_slot_fn)(unsigned long target, void *context);

static inline int kpm_symbol_prefix(const char *name, char a, char b)
{
    return name && name[0] == a && name[1] == b && name[2] == '_' && name[3];
}

static inline int kpm_symbol_is_function_pointer(const char *name)
{
    if (kpm_symbol_prefix(name, 'k', 'f')) return 1;
    const char *special[] = { "printk", "kallsyms_lookup_name", "kallsyms_on_each_symbol" };
    unsigned int i;
    for (i = 0; i < sizeof(special) / sizeof(special[0]); i++) {
        const char *a = name, *b = special[i];
        if (!a) continue;
        while (*a && *a == *b) { a++; b++; }
        if (!*a && !*b) return 1;
    }
    return 0;
}

static inline int kpm_symbol_resolve(const char *name, kpm_symbol_lookup_fn compatibility,
                                     kpm_symbol_lookup_fn kernel_function,
                                     kpm_symbol_lookup_fn kernel_data,
                                     kpm_symbol_slot_fn slot, void *context,
                                     struct kpm_symbol_resolution *result)
{
    unsigned long address = 0, target = 0;
    int function_pointer = kpm_symbol_is_function_pointer(name);
    int data_pointer = kpm_symbol_prefix(name, 'k', 'v');
    result->address = result->target = 0;
    result->kind = KPM_SYMBOL_DIRECT;
    if (!name || !name[0]) return -1;
    if (compatibility) address = compatibility(name, context);
    if (address && (function_pointer || data_pointer)) {
        target = *(const unsigned long *)address;
        if (target) {
            if (slot) address = slot(target, context);
            if (!address) return -2;
            result->address = address;
            result->target = target;
            result->kind = function_pointer ? KPM_SYMBOL_FUNCTION_POINTER : KPM_SYMBOL_DATA_POINTER;
            return 0;
        }
        /* A null predeclared kf_* slot is not a successfully resolved function. */
        address = 0;
    }
    if (address) {
        result->address = result->target = address;
        return 0;
    }
    if (function_pointer || data_pointer) {
        const char *base = kpm_symbol_prefix(name, 'k', 'f') || data_pointer ? name + 3 : name;
        kpm_symbol_lookup_fn lookup = data_pointer ? kernel_data : kernel_function;
        if (lookup) target = lookup(base, context);
        if (!target) return -1;
        address = slot ? slot(target, context) : 0;
        if (!address) return -2;
        result->address = address;
        result->target = target;
        result->kind = function_pointer ? KPM_SYMBOL_FUNCTION_POINTER : KPM_SYMBOL_DATA_POINTER;
        return 0;
    }
    /* Exact symbols preserve data identity; compiler-suffixed functions are fallback only. */
    if (kernel_data) address = kernel_data(name, context);
    if (!address && kernel_function) address = kernel_function(name, context);
    if (!address) return -1;
    result->address = result->target = address;
    return 0;
}

#endif
