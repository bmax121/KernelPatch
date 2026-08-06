// SPDX-License-Identifier: GPL-2.0-or-later
/* LKM backends required by kernel/base/hook.c. */
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/cacheflush.h>

#include "../include/kp_lkm.h"
#include <hook.h>
#include "../infra/patch_memory.h"
#include "../infra/symbol_resolver.h"

struct kp_hook_mem {
	struct list_head list;
	uintptr_t origin;
	enum hook_type type;
	void *region;
	union {
		hook_t hook;
		hook_chain_t chain;
		fp_hook_chain_t fp_chain;
	} *payload;
};

static LIST_HEAD(kp_hook_mems);
static DEFINE_MUTEX(kp_hook_lock);
static void *(*kp_hook_module_alloc)(unsigned long size);
static void (*kp_hook_module_memfree)(void *region);
static void (*kp_hook_flush_icache_all)(void);
static int (*kp_hook_set_memory_x)(unsigned long addr, int numpages);

__attribute__((no_sanitize("cfi")))
static void *kp_hook_exec_alloc(unsigned long size)
{
	void *p = kp_hook_module_alloc(size);
	/* GKI module_alloc returns PAGE_KERNEL (PXN set, NX). Hook trampolines
	 * live here and must be executable. */
	if (p && kp_hook_set_memory_x)
		kp_hook_set_memory_x((unsigned long)p, (size + PAGE_SIZE - 1) >> PAGE_SHIFT);
	return p;
}

__attribute__((no_sanitize("cfi")))
static void kp_hook_exec_free(void *region)
{
	kp_hook_module_memfree(region);
}

__attribute__((no_sanitize("cfi")))
static void kp_hook_flush_all(void)
{
	if (kp_hook_flush_icache_all)
		kp_hook_flush_icache_all();
}

int kp_hook_runtime_init(void)
{
	kp_hook_module_alloc = (void *)kp_resolve_symbol("module_alloc");
	kp_hook_module_memfree = (void *)kp_resolve_symbol("module_memfree");
	kp_hook_flush_icache_all = (void *)kp_resolve_symbol("flush_icache_all");
	kp_hook_set_memory_x = (int (*)(unsigned long, int))kp_resolve_symbol("set_memory_x");
	if (!kp_hook_module_alloc || !kp_hook_module_memfree)
		return -ENOSYS;
	logki("KPM hook runtime ready (set_memory_x=%px)\n", kp_hook_set_memory_x);
	return 0;
}

void *hook_mem_zalloc(uintptr_t origin, enum hook_type type)
{
	struct kp_hook_mem *mem;
	size_t size;

	switch (type) {
	case INLINE:
		size = sizeof(hook_t);
		break;
	case INLINE_CHAIN:
		size = sizeof(hook_chain_t);
		break;
	case FUNCTION_POINTER_CHAIN:
		size = sizeof(fp_hook_chain_t);
		break;
	default:
		return NULL;
	}

	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return NULL;
	mem->region = kp_hook_exec_alloc(PAGE_ALIGN(size));
	if (!mem->region) {
		kfree(mem);
		return NULL;
	}
	memset(mem->region, 0, PAGE_ALIGN(size));
	mem->payload = mem->region;
	mem->origin = origin;
	mem->type = type;
	mutex_lock(&kp_hook_lock);
	list_add_tail(&mem->list, &kp_hook_mems);
	mutex_unlock(&kp_hook_lock);
	return mem->payload;
}

void *hook_get_mem_from_origin(uint64_t origin)
{
	struct kp_hook_mem *mem;
	void *result = NULL;

	mutex_lock(&kp_hook_lock);
	list_for_each_entry(mem, &kp_hook_mems, list) {
		if (mem->origin == origin) {
			result = mem->payload;
			break;
		}
	}
	mutex_unlock(&kp_hook_lock);
	return result;
}

void hook_mem_free(void *payload)
{
	struct kp_hook_mem *mem, *tmp;

	mutex_lock(&kp_hook_lock);
	list_for_each_entry_safe(mem, tmp, &kp_hook_mems, list) {
		if (mem->payload == payload) {
			list_del(&mem->list);
			mutex_unlock(&kp_hook_lock);
			kp_hook_exec_free(mem->region);
			kfree(mem);
			return;
		}
	}
	mutex_unlock(&kp_hook_lock);
}

int hotpatch(void *addrs[], uint32_t values[], int count)
{
	int i, start, rc;

	for (start = 0; start < count; start = i) {
		for (i = start + 1; i < count; i++) {
			if ((char *)addrs[i] != (char *)addrs[start] +
						 (i - start) * sizeof(values[0]))
				break;
		}
		rc = kp_patch_text(addrs[start], &values[start],
				   (i - start) * sizeof(values[0]),
				   KP_PATCH_TEXT_FLUSH_DCACHE | KP_PATCH_TEXT_FLUSH_ICACHE);
		if (rc)
			return rc;
	}
	return 0;
}

void flush_icache_all(void)
{
	kp_hook_flush_all();
}
