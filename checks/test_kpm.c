/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host unit tests for the KPM loader: link arena, symbol resolution, and
 * cross-module dependency policy.  Build:
 *   gcc -O2 -Wall -Wextra -o /tmp/test_kpm checks/test_kpm.c && /tmp/test_kpm
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../kernel/include/kpmlink.h"
#include "../kernel/include/kpmsymbol.h"
#include "../kernel/include/kpmdep.h"

struct fixture {
    unsigned char image[2048] __attribute__((aligned(16)));
    struct kpm_link_state link;
    unsigned long known_slot;
    unsigned long zero_slot;
};

static unsigned long compat(const char *name, void *context)
{
    struct fixture *f = context;
    if (!strcmp(name, "kf_known")) return (unsigned long)&f->known_slot;
    if (!strcmp(name, "kf_late")) return (unsigned long)&f->zero_slot;
    if (!strcmp(name, "compat_api")) return 0x1000;
    return 0;
}

static unsigned long kernel_function(const char *name, void *context)
{
    (void)context;
    if (!strcmp(name, "late") || !strcmp(name, "new_function")) return 0xffff000001000000UL;
    if (!strcmp(name, "printk")) return 0xffff000002000000UL;
    return 0;
}

static unsigned long kernel_data(const char *name, void *context)
{
    (void)context;
    return !strcmp(name, "kernel_data") ? 0xffff000003000000UL : 0;
}

static unsigned long slot(unsigned long value, void *context)
{
    struct fixture *f = context;
    return kpm_link_pointer(&f->link, f->image, value);
}

static void test_resolver(void)
{
    struct fixture f = { .known_slot = 0xffff000004000000UL };
    unsigned int size = 256;
    struct kpm_symbol_resolution r;
    assert(!kpm_link_reserve(&f.link, &size, 8));
#define RESOLVE(n) kpm_symbol_resolve(n, compat, kernel_function, kernel_data, slot, &f, &r)
    /* Compatibility table hit with a populated pointer slot. */
    assert(!RESOLVE("kf_known"));
    assert(r.kind == KPM_SYMBOL_FUNCTION_POINTER && *(unsigned long *)r.address == f.known_slot);
    assert(r.address != (unsigned long)&f.known_slot);
    /* Compatibility slot present but NULL -> fall back to the kernel. */
    assert(!RESOLVE("kf_late"));
    assert(*(unsigned long *)r.address == 0xffff000001000000UL);
    /* No slot at all: a fresh one is allocated and populated. */
    assert(!RESOLVE("kf_new_function"));
    assert(r.target == 0xffff000001000000UL);
    /* Plain (non-pointer) kernel symbol resolves to its own address. */
    assert(!RESOLVE("new_function"));
    assert(r.address == 0xffff000001000000UL && r.kind == KPM_SYMBOL_DIRECT);
    /* kv_* data pointer slot. */
    assert(!RESOLVE("kernel_data"));
    assert(r.address == 0xffff000003000000UL);
    assert(!RESOLVE("kv_kernel_data"));
    assert(*(unsigned long *)r.address == 0xffff000003000000UL && r.kind == KPM_SYMBOL_DATA_POINTER);
    /* printk is a pointer variable in the KPM headers. */
    assert(!RESOLVE("printk"));
    assert(*(unsigned long *)r.address == 0xffff000002000000UL);
    /* Non-pointer compatibility entry. */
    assert(!RESOLVE("compat_api") && r.address == 0x1000);
    /* Unresolvable names. */
    assert(RESOLVE("missing") == -1 && !r.address);
    assert(RESOLVE("") == -1);
    assert(RESOLVE(NULL) == -1);
    assert(RESOLVE("k") == -1);
    assert(RESOLVE("kf") == -1);
    assert(RESOLVE("kf_") == -1);
    /* No slot allocator: must report arena exhaustion, not success. */
    assert(kpm_symbol_resolve("kf_new_function", compat, kernel_function, kernel_data,
                              NULL, &f, &r) == -2);
#undef RESOLVE
}

static void test_link(void)
{
    unsigned char image[256] __attribute__((aligned(16))) = { 0 };
    unsigned int size = 17;
    struct kpm_link_state state;
    unsigned long plt;
    struct kpm_link_slot *s;
    unsigned long base = 0x10000000UL;

    assert(sizeof(struct kpm_link_slot) == KPM_LINK_SLOT_SIZE);
    assert(!kpm_link_reserve(&state, &size, 2));
    assert(state.offset == 32 && size == 96);
    plt = kpm_link_plt(&state, image, 0xffff000001234000UL);
    s = (void *)plt;
    assert(s->insn[0] == 0xd503245f && s->insn[1] == 0x58000070);
    assert(s->insn[2] == 0xd61f0200 && s->target == 0xffff000001234000UL);
    assert(kpm_link_pointer(&state, image, s->target) == (unsigned long)&s->target);
    assert(state.used == 1);
    /* Slots are deduplicated by target. */
    assert(kpm_link_plt(&state, image, 0x4000));
    assert(!kpm_link_plt(&state, image, 0x5000));
    /* Capacity and image-size bounds. */
    size = KPM_LINK_MAX_IMAGE;
    assert(kpm_link_reserve(&state, &size, 1) == -1);
    size = 16;
    assert(kpm_link_reserve(&state, &size, ~0UL) == -1);
    /* Branch range check (+-128MB, 4-byte aligned). */
    assert(kpm_link_branch_in_range(base, base - (1UL << 27)));
    assert(kpm_link_branch_in_range(base, base + (1UL << 27) - 4));
    assert(!kpm_link_branch_in_range(base, base + (1UL << 27)));
    assert(!kpm_link_branch_in_range(base, base - (1UL << 27) - 4));
    assert(!kpm_link_branch_in_range(base, base + 1));
}

static int put_calls;

static void put_cb(void *provider, void *ctx)
{
    (void)provider;
    (*(int *)ctx)++;
}

static void test_deps(void)
{
    void *deps[4];
    unsigned int count = 0;
    int a = 0, b = 0;
    void *pa = &a, *pb = &b;

    /* Recording is idempotent per provider. */
    assert(kpm_dep_record(deps, &count, 4, pa) == 1);
    assert(kpm_dep_record(deps, &count, 4, pa) == 0);
    assert(kpm_dep_record(deps, &count, 4, pb) == 1);
    assert(count == 2);
    assert(kpm_dep_record(deps, &count, 4, (void *)1) == 1);
    assert(kpm_dep_record(deps, &count, 4, (void *)2) == 1);
    assert(count == 4);
    /* Full table must be reported, never silently accepted. */
    assert(kpm_dep_record(deps, &count, 4, (void *)3) == -1);

    /* Forgetting an edge invokes the callback exactly once. */
    put_calls = 0;
    assert(kpm_dep_forget(deps, &count, pa, put_cb, &put_calls) == 1);
    assert(put_calls == 1);
    assert(kpm_dep_forget(deps, &count, pa, put_cb, &put_calls) == 0);
    assert(put_calls == 1);
    assert(count == 3);
    assert(kpm_dep_forget(deps, &count, pb, NULL, NULL) == 1);
    assert(count == 2);
    /* Remaining entries are the two synthetic providers, order-independent. */
    assert((deps[0] == (void *)1 || deps[0] == (void *)2) &&
           (deps[1] == (void *)1 || deps[1] == (void *)2) && deps[0] != deps[1]);
    assert(kpm_dep_record(NULL, &count, 4, pa) == -1);
    assert(kpm_dep_record(deps, &count, 0, pa) == -1);
}

int main(void)
{
    test_link();
    test_resolver();
    test_deps();
    puts("PASS: link arena, symbol resolution, dependency policy");
    return 0;
}
