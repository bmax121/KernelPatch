/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_KPMDEP_H_
#define _KP_KPMDEP_H_

/* LKM-style dependency tracking: an importer records its providers; a provider
 * counts importing modules.  Unload order mirrors the kernel module loader:
 * a provider with live importers refuses (-EBUSY), an importer releases its
 * providers when it goes away, and a failed load rolls its edges back. */

#define KPM_DEP_MAX 16

/* 1 = new edge recorded, 0 = edge already present, -1 = table full. */
static inline int kpm_dep_record(void **deps, unsigned int *count, unsigned int cap, void *provider)
{
    unsigned int i;
    if (!deps || !count || !provider || cap > KPM_DEP_MAX) return -1;
    for (i = 0; i < *count; i++) {
        if (deps[i] == provider) return 0;
    }
    if (*count >= cap) return -1;
    deps[(*count)++] = provider;
    return 1;
}

/* Drops one recorded edge, invoking put(provider, ctx) exactly once for it.
 * 1 = dropped, 0 = no such edge. */
static inline int kpm_dep_forget(void **deps, unsigned int *count, void *provider,
                                 void (*put)(void *provider, void *ctx), void *ctx)
{
    unsigned int i;
    if (!deps || !count) return 0;
    for (i = 0; i < *count; i++) {
        if (deps[i] == provider) {
            deps[i] = deps[*count - 1];
            (*count)--;
            if (put) put(provider, ctx);
            return 1;
        }
    }
    return 0;
}

#endif
