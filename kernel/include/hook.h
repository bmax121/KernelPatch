#ifndef _KP_HOOK_H_
#define _KP_HOOK_H_

#include <stdint.h>
#include <stdbool.h>
#include <log.h>

#define HOOK_INTO_BRANCH_FUNC

typedef enum
{
    HOOK_NO_ERR = 0,
    HOOK_INPUT_NULL,
    HOOK_NO_MEM,
    HOOK_BAD_RELO,
    HOOK_TRANSIT_NO_MEM,
    HOOK_CHAIN_FULL,
    HOOK_NOT_HOOK,
} hook_err_t;

#define local_offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#define local_container_of(ptr, type, member) ({ (type *)((char *)(ptr)-local_offsetof(type, member)); })

#define HOOK_MEM_REGION_NUM 4
#define TRAMPOLINE_NUM 4
#define RELOCATE_INST_NUM (TRAMPOLINE_NUM * 7 + 4)
#define HOOK_CHAIN_NUM 4

#define TRANSIT_INST_NUM 64
#define TRANSIT_ALIGN 32
#define ARM64_NOP 0xd503201f

typedef struct
{
    // in
    uint64_t func_addr;
    uint64_t origin_addr;
    uint64_t replace_addr;
    uint64_t relo_addr;
    // out
    bool pac;
    uint32_t origin_insts[TRAMPOLINE_NUM];
    uint32_t tramp_insts_len;
    uint32_t tramp_insts[TRAMPOLINE_NUM];
    uint32_t relo_insts_len;
    uint32_t relo_insts[RELOCATE_INST_NUM];
} hook_t;

struct _hook_chain;

typedef struct
{
    struct _hook_chain *chain;
    bool early_ret;
    uint64_t ret;
} hook_fdata0_t;

typedef struct
{
    struct _hook_chain *chain;
    bool early_ret;
    uint64_t ret;
    uint64_t arg0;
} hook_fdata1_t;

typedef struct
{
    struct _hook_chain *chain;
    bool early_ret;
    uint64_t ret;
    uint64_t arg0;
    uint64_t arg1;
} hook_fdata2_t;

typedef struct
{
    struct _hook_chain *chain;
    bool early_ret;
    uint64_t ret;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
} hook_fdata3_t;

typedef struct
{
    struct _hook_chain *chain;
    bool early_ret;
    uint64_t ret;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
} hook_fdata4_t;

typedef struct
{
    struct _hook_chain *chain;
    bool early_ret;
    uint64_t ret;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
    uint64_t arg7;
} hook_fdata8_t;

typedef struct
{
    struct _hook_chain *chain;
    bool early_ret;
    uint64_t ret;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
    uint64_t arg7;
    uint64_t arg8;
    uint64_t arg9;
    uint64_t arg10;
    uint64_t arg11;
} hook_fdata12_t;

typedef void (*hook_chain0_callback)(hook_fdata0_t *fdata, void *udata);
typedef void (*hook_chain1_callback)(hook_fdata1_t *fdata, void *udata);
typedef void (*hook_chain2_callback)(hook_fdata2_t *fdata, void *udata);
typedef void (*hook_chain3_callback)(hook_fdata3_t *fdata, void *udata);
typedef void (*hook_chain4_callback)(hook_fdata4_t *fdata, void *udata);
typedef void (*hook_chain8_callback)(hook_fdata8_t *fdata, void *udata);
typedef void (*hook_chain12_callback)(hook_fdata12_t *fdata, void *udata);

typedef struct _hook_chain
{
    hook_t hook;
    void *udata[HOOK_CHAIN_NUM];
    void *befores[HOOK_CHAIN_NUM];
    void *afters[HOOK_CHAIN_NUM];
    uint32_t transit[TRANSIT_ALIGN / 4 + TRANSIT_INST_NUM];
} hook_chain_t;

bool hook_mem_add(uint64_t start, int32_t size);
hook_chain_t *hook_mem_alloc();
void hook_mem_free(hook_chain_t *free);
hook_chain_t *hook_get_chain_from_origin(uint64_t origin_addr);

int32_t branch_from_to(uint32_t *tramp_buf, uint64_t src_addr, uint64_t dst_addr);
int32_t branch_relative(uint32_t *buf, uint64_t src_addr, uint64_t dst_addr);
int32_t branch_absolute(uint32_t *buf, uint64_t addr);

#ifdef HOOK_INTO_BRANCH_FUNC
uint64_t relo_func(uint64_t addr);
#else
static inline uint64_t relo_func(uint64_t addr)
{
    return addr;
}
#endif

hook_err_t hook_prepare(hook_t *hook);
void hook_install(hook_t *hook);
void hook_uninstall(hook_t *hook);
hook_err_t hook(void *func, void *replace, void **backup);
void unhook(void *func);

// todo: hook priority
hook_err_t hook_chain_prepare(hook_chain_t *chain, int32_t argno);
static inline void hook_chain_install(hook_chain_t *chain)
{
    hook_install(&chain->hook);
}
static inline void hook_chain_uninstall(hook_chain_t *chain)
{
    hook_uninstall(&chain->hook);
}
hook_err_t hook_chain_add(hook_chain_t *chain, void *before, void *after, void *udata);
void hook_chain_remove(hook_chain_t *chain, void *before, void *after);
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata, void **backup);
void hook_unwrap(void *func, void *before, void *after);

static inline hook_err_t hook_wrap0(void *func, hook_chain0_callback before, hook_chain0_callback after, void *udata,
                                    void **backup)
{
    return hook_wrap(func, 0, before, after, udata, backup);
}

static inline hook_err_t hook_wrap1(void *func, hook_chain1_callback before, hook_chain1_callback after, void *udata,
                                    void **backup)
{
    return hook_wrap(func, 1, before, after, udata, backup);
}

static inline hook_err_t hook_wrap2(void *func, hook_chain2_callback before, hook_chain2_callback after, void *udata,
                                    void **backup)
{
    return hook_wrap(func, 2, before, after, udata, backup);
}

static inline hook_err_t hook_wrap3(void *func, hook_chain3_callback before, hook_chain3_callback after, void *udata,
                                    void **backup)
{
    return hook_wrap(func, 3, before, after, udata, backup);
}

static inline hook_err_t hook_wrap4(void *func, hook_chain4_callback before, hook_chain4_callback after, void *udata,
                                    void **backup)
{
    return hook_wrap(func, 4, before, after, udata, backup);
}

static inline hook_err_t hook_wrap8(void *func, hook_chain8_callback before, hook_chain8_callback after, void *udata,
                                    void **backup)
{
    return hook_wrap(func, 8, before, after, udata, backup);
}

static inline hook_err_t hook_wrap12(void *func, hook_chain12_callback before, hook_chain12_callback after, void *udata,
                                     void **backup)
{
    return hook_wrap(func, 12, before, after, udata, backup);
}

static inline void hook_unwrapn(void *func, void *before, void *after)
{
    return hook_unwrap(func, before, after);
}

#endif
