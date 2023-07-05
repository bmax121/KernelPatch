#include "hook.h"

#include <stdint.h>

// todo: refactor

static uint64_t mem_region_start[HOOK_MEM_REGION_NUM] = { 0 };
static uint64_t mem_region_end[HOOK_MEM_REGION_NUM] = { 0 };

typedef struct
{
    bool using;
    hook_chain_t chain;
} hook_mem_warp_t;

bool hook_mem_add(uint64_t start, int32_t size)
{
    for (uint64_t i = start; i < start + size; i += 8) { *(uint64_t *)i = 0; }

    for (int i = 0; i < HOOK_MEM_REGION_NUM; i++) {
        if (!mem_region_start[i]) {
            mem_region_start[i] = start;
            mem_region_end[i] = start + size;
            return true;
        }
    }
    return false;
}

hook_chain_t *hook_mem_alloc()
{
    for (int i = 0; i < HOOK_MEM_REGION_NUM; i++) {
        uint64_t start = mem_region_start[i];
        if (!start) continue;
        for (uint64_t addr = start; addr < mem_region_end[i]; addr += sizeof(hook_mem_warp_t)) {
            hook_mem_warp_t *wrap = (hook_mem_warp_t *)addr;
            // todo: lock
            if (wrap->using) continue;

            wrap->using = true;

            for (int j = offsetof(hook_mem_warp_t, chain); j < sizeof(hook_mem_warp_t); j += 8) {
                *(uint64_t *)(addr + j) = 0;
            }
            return &wrap->chain;
        }
    }
    return 0;
}

inline void hook_mem_free(hook_chain_t *free)
{
    hook_mem_warp_t *warp = container_of(free, hook_mem_warp_t, chain);
    warp->using = false;
}

hook_chain_t *hook_get_chain_from_origin(uint64_t origin_addr)
{
    for (int i = 0; i < HOOK_MEM_REGION_NUM; i++) {
        uint64_t start = mem_region_start[i];
        if (!start) continue;
        for (uint64_t addr = start; addr < mem_region_end[i]; addr += sizeof(hook_mem_warp_t)) {
            hook_mem_warp_t *wrap = (hook_mem_warp_t *)addr;
            if (wrap->using && wrap->chain.hook.origin_addr == origin_addr) { return &wrap->chain; }
        }
    }
    return 0;
}
