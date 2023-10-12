/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A symbol table (symtab) maintains associations between symbol
 * strings and datum values.  The type of the datum values
 * is arbitrary.  The symbol table type is implemented
 * using the hash table type (hashtab).
 *
 * Author : Stephen Smalley, <sds@tycho.nsa.gov>
 */
#ifndef _SS_SYMTAB_H_
#define _SS_SYMTAB_H_

#include <ksyms.h>
#include <common.h>

#include "hashtab.h"

struct symtab
{
    struct hashtab table; /* hash table (keyed on a string) */
    u32 nprim; /* number of primary names in table */
};

struct symtab_lt580
{
    struct hashtab *table; /* hash table (keyed on a string) */
    u32 nprim; /* number of primary names in table */
};

static inline struct hashtab *symtab_table_p(struct symtab *symtab)
{
    if (kver < VERSION(5, 8, 0)) {
        return ((struct symtab_lt580 *)symtab)->table;
    }
    return &symtab->table;
}

int kfunc_def(symtab_insert)(struct symtab *s, char *name, void *datum);
void *kfunc_def(symtab_search)(struct symtab *s, const char *name);

static inline int symtab_insert(struct symtab *s, char *name, void *datum)
{
    int rc;
    if (kfunc(symtab_insert))
        rc = kfunc(symtab_insert)(s, name, datum);
    else
        rc = kfunc(hashtab_insert)(s, name, datum);
    return rc;
}

static inline void *symtab_search(struct symtab *s, const char *name)
{
    void *ret;
    if (kfunc(symtab_search))
        ret = kfunc(symtab_search)(s, name);
    else
        ret = kfunc(hashtab_search)(s, name);
    return ret;
}

#endif /* _SS_SYMTAB_H_ */
