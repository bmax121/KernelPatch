/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_HOOK_H_
#define _KP_HOOK_H_

#include <stdint.h>
#include <log.h>

#define HOOK_INTO_BRANCH_FUNC

typedef enum
{
    HOOK_NO_ERR = 0,
    HOOK_BAD_ADDRESS = 4095,
    HOOK_DUPLICATED = 4094,
    HOOK_NO_MEM = 4093,
    HOOK_BAD_RELO = 4092,
    HOOK_TRANSIT_NO_MEM = 4091,
    HOOK_CHAIN_FULL = 4090,
} hook_err_t;

enum hook_type
{
    NONE = 0,
    INLINE,
    INLINE_CHAIN,
    FUNCTION_POINTER_CHAIN,
};

typedef int8_t chain_item_state;

#define CHAIN_ITEM_STATE_EMPTY 0
#define CHAIN_ITEM_STATE_READY 1
#define CHAIN_ITEM_STATE_BUSY 2

#define local_offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#define local_container_of(ptr, type, member) ({ (type *)((char *)(ptr)-local_offsetof(type, member)); })

#define HOOK_MEM_REGION_NUM 4
#define TRAMPOLINE_NUM 4
#define RELOCATE_INST_NUM (TRAMPOLINE_NUM * 8 + 8)

#define HOOK_CHAIN_NUM 0x10
#define TRANSIT_INST_NUM 0x60

#define FP_HOOK_CHAIN_NUM 0x20

#define ARM64_NOP 0xd503201f
#define ARM64_BTI_C 0xd503245f
#define ARM64_BTI_J 0xd503249f
#define ARM64_BTI_JC 0xd50324df

typedef struct
{
    // in
    uint64_t func_addr;
    uint64_t origin_addr;
    uint64_t replace_addr;
    uint64_t relo_addr;
    // out
    int32_t tramp_insts_num;
    int32_t relo_insts_num;
    uint32_t origin_insts[TRAMPOLINE_NUM] __attribute__((aligned(8)));
    uint32_t tramp_insts[TRAMPOLINE_NUM] __attribute__((aligned(8)));
    uint32_t relo_insts[RELOCATE_INST_NUM] __attribute__((aligned(8)));
} hook_t __attribute__((aligned(8)));

struct _hook_chain;

#define HOOK_LOCAL_DATA_NUM 8

typedef struct
{
    union
    {
        struct
        {
            uint64_t data0;
            uint64_t data1;
            uint64_t data2;
            uint64_t data3;
            uint64_t data4;
            uint64_t data5;
            uint64_t data6;
            uint64_t data7;
        };
        uint64_t data[HOOK_LOCAL_DATA_NUM];
    };
} hook_local_t;

typedef struct
{
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union
    {
        struct
        {
        };
        uint64_t args[0];
    };
} hook_fargs0_t __attribute__((aligned(8)));

typedef struct
{
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union
    {
        struct
        {
            uint64_t arg0;
            uint64_t arg1;
            uint64_t arg2;
            uint64_t arg3;
        };
        uint64_t args[4];
    };
} hook_fargs4_t __attribute__((aligned(8)));

typedef hook_fargs4_t hook_fargs1_t;
typedef hook_fargs4_t hook_fargs2_t;
typedef hook_fargs4_t hook_fargs3_t;

typedef struct
{
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union
    {
        struct
        {
            uint64_t arg0;
            uint64_t arg1;
            uint64_t arg2;
            uint64_t arg3;
            uint64_t arg4;
            uint64_t arg5;
            uint64_t arg6;
            uint64_t arg7;
        };
        uint64_t args[8];
    };
} hook_fargs8_t __attribute__((aligned(8)));

typedef hook_fargs8_t hook_fargs5_t;
typedef hook_fargs8_t hook_fargs6_t;
typedef hook_fargs8_t hook_fargs7_t;

typedef struct
{
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union
    {
        struct
        {
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
        };
        uint64_t args[12];
    };
} hook_fargs12_t __attribute__((aligned(8)));

typedef hook_fargs12_t hook_fargs9_t;
typedef hook_fargs12_t hook_fargs10_t;
typedef hook_fargs12_t hook_fargs11_t;

typedef void (*hook_chain0_callback)(hook_fargs0_t *fargs, void *udata);
typedef void (*hook_chain1_callback)(hook_fargs1_t *fargs, void *udata);
typedef void (*hook_chain2_callback)(hook_fargs2_t *fargs, void *udata);
typedef void (*hook_chain3_callback)(hook_fargs3_t *fargs, void *udata);
typedef void (*hook_chain4_callback)(hook_fargs4_t *fargs, void *udata);
typedef void (*hook_chain5_callback)(hook_fargs5_t *fargs, void *udata);
typedef void (*hook_chain6_callback)(hook_fargs6_t *fargs, void *udata);
typedef void (*hook_chain7_callback)(hook_fargs7_t *fargs, void *udata);
typedef void (*hook_chain8_callback)(hook_fargs8_t *fargs, void *udata);
typedef void (*hook_chain9_callback)(hook_fargs9_t *fargs, void *udata);
typedef void (*hook_chain10_callback)(hook_fargs10_t *fargs, void *udata);
typedef void (*hook_chain11_callback)(hook_fargs11_t *fargs, void *udata);
typedef void (*hook_chain12_callback)(hook_fargs12_t *fargs, void *udata);

typedef struct _hook_chain
{
    // must be the first element
    hook_t hook;
    int32_t chain_items_max;
    chain_item_state states[HOOK_CHAIN_NUM];
    void *udata[HOOK_CHAIN_NUM];
    void *befores[HOOK_CHAIN_NUM];
    void *afters[HOOK_CHAIN_NUM];
    uint32_t transit[TRANSIT_INST_NUM];
} hook_chain_t __attribute__((aligned(8)));

typedef struct
{
    uintptr_t fp_addr;
    uint64_t replace_addr;
    uint64_t origin_fp;
} fp_hook_t __attribute__((aligned(8)));

typedef struct _fphook_chain
{
    fp_hook_t hook;
    int32_t chain_items_max;
    chain_item_state states[FP_HOOK_CHAIN_NUM];
    void *udata[FP_HOOK_CHAIN_NUM];
    void *befores[FP_HOOK_CHAIN_NUM];
    void *afters[FP_HOOK_CHAIN_NUM];
    uint32_t transit[TRANSIT_INST_NUM];
} fp_hook_chain_t __attribute__((aligned(8)));

static inline int is_bad_address(void *addr)
{
    return ((uint64_t)addr & 0x8000000000000000) != 0x8000000000000000;
}

int32_t branch_from_to(uint32_t *tramp_buf, uint64_t src_addr, uint64_t dst_addr);
int32_t branch_relative(uint32_t *buf, uint64_t src_addr, uint64_t dst_addr);
int32_t branch_absolute(uint32_t *buf, uint64_t addr);
int32_t ret_absolute(uint32_t *buf, uint64_t addr);

hook_err_t hook_prepare(hook_t *hook);
void hook_install(hook_t *hook);
void hook_uninstall(hook_t *hook);

/**
 * @brief Inline-hook function which address is @param func with function @param replace, 
 * after hook, original @param func is backuped in @param backup.
 * 
 * @note If multiple modules hook this function simultaneously, 
 * it will cause abnormality when unload the modules. Please use hook_wrap instead
 * 
 * @see hook_wrap
 * 
 * @param func 
 * @param replace 
 * @param backup 
 * @return hook_err_t 
 */
hook_err_t hook(void *func, void *replace, void **backup);

/**
 * @brief unhook of hooked function
 * 
 * @param func 
 */
void unhook(void *func);

/**
 * @brief 
 * 
 * @param chain 
 * @param before 
 * @param after 
 * @param udata 
 * @return hook_err_t 
 */
hook_err_t hook_chain_add(hook_chain_t *chain, void *before, void *after, void *udata);
/**
 * @brief 
 * 
 * @param chain 
 * @param before 
 * @param after 
 */
void hook_chain_remove(hook_chain_t *chain, void *before, void *after);

/**
 * @brief Wrap a function with before and after function. 
 * The same function can do hook and unhook multiple times 
 * 
 * @see hook_chain0_callback
 * @see hook_fargs0_t
 * 
 * @param func The address of function 
 * @param argno The number of method arguments
 * @param before This function will be called before hooked function, 
 * the type of before is hook_chain{n}_callback which n is equal to argno.
 * @param after The same as before but will be call after hooked function
 * @param udata 
 * @return hook_err_t 
 */
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata);

/**
 * @brief 
 * 
 * @param func 
 * @param before 
 * @param after 
 * @param remove 
 */
void hook_unwrap_remove(void *func, void *before, void *after, int remove);

static inline void hook_unwrap(void *func, void *before, void *after)
{
    return hook_unwrap_remove(func, before, after, 1);
}

static inline void *hook_chain_origin_func(void *hook_args)
{
    hook_fargs0_t *args = (hook_fargs0_t *)hook_args;
    hook_chain_t *chain = (hook_chain_t *)args->chain;
    return (void *)chain->hook.relo_addr;
}

/**
 * @brief 
 * 
 * @param fp_addr 
 * @param replace 
 * @param backup 
 */
void fp_hook(uintptr_t fp_addr, void *replace, void **backup);

/**
 * @brief 
 * 
 * @param fp_addr 
 * @param backup 
 */
void fp_unhook(uintptr_t fp_addr, void *backup);

/**
 * @brief 
 * 
 * @param fp_addr 
 * @param argno 
 * @param before 
 * @param after 
 * @param udata 
 * @return hook_err_t 
 */
hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata);

/**
 * @brief 
 * 
 * @param fp_addr 
 * @param before 
 * @param after 
 */
void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after);

static inline void hook_chain_install(hook_chain_t *chain)
{
    hook_install(&chain->hook);
}

static inline void hook_chain_uninstall(hook_chain_t *chain)
{
    hook_uninstall(&chain->hook);
}

static inline hook_err_t hook_wrap0(void *func, hook_chain0_callback before, hook_chain0_callback after, void *udata)
{
    return hook_wrap(func, 0, before, after, udata);
}

static inline hook_err_t hook_wrap1(void *func, hook_chain1_callback before, hook_chain1_callback after, void *udata)
{
    return hook_wrap(func, 1, before, after, udata);
}

static inline hook_err_t hook_wrap2(void *func, hook_chain2_callback before, hook_chain2_callback after, void *udata)
{
    return hook_wrap(func, 2, before, after, udata);
}

static inline hook_err_t hook_wrap3(void *func, hook_chain3_callback before, hook_chain3_callback after, void *udata)
{
    return hook_wrap(func, 3, before, after, udata);
}

static inline hook_err_t hook_wrap4(void *func, hook_chain4_callback before, hook_chain4_callback after, void *udata)
{
    return hook_wrap(func, 4, before, after, udata);
}

static inline hook_err_t hook_wrap5(void *func, hook_chain5_callback before, hook_chain5_callback after, void *udata)
{
    return hook_wrap(func, 5, before, after, udata);
}

static inline hook_err_t hook_wrap6(void *func, hook_chain6_callback before, hook_chain6_callback after, void *udata)
{
    return hook_wrap(func, 6, before, after, udata);
}

static inline hook_err_t hook_wrap7(void *func, hook_chain7_callback before, hook_chain7_callback after, void *udata)
{
    return hook_wrap(func, 7, before, after, udata);
}

static inline hook_err_t hook_wrap8(void *func, hook_chain8_callback before, hook_chain8_callback after, void *udata)
{
    return hook_wrap(func, 8, before, after, udata);
}

static inline hook_err_t hook_wrap9(void *func, hook_chain9_callback before, hook_chain9_callback after, void *udata)
{
    return hook_wrap(func, 9, before, after, udata);
}

static inline hook_err_t hook_wrap10(void *func, hook_chain10_callback before, hook_chain10_callback after, void *udata)
{
    return hook_wrap(func, 10, before, after, udata);
}

static inline hook_err_t hook_wrap11(void *func, hook_chain11_callback before, hook_chain11_callback after, void *udata)
{
    return hook_wrap(func, 11, before, after, udata);
}

static inline hook_err_t hook_wrap12(void *func, hook_chain12_callback before, hook_chain12_callback after, void *udata)
{
    return hook_wrap(func, 12, before, after, udata);
}

static inline hook_err_t fp_hook_wrap0(uintptr_t fp_addr, hook_chain0_callback before, hook_chain0_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 0, before, after, udata);
}

static inline hook_err_t fp_hook_wrap1(uintptr_t fp_addr, hook_chain1_callback before, hook_chain1_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 1, before, after, udata);
}

static inline hook_err_t fp_hook_wrap2(uintptr_t fp_addr, hook_chain2_callback before, hook_chain2_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 2, before, after, udata);
}

static inline hook_err_t fp_hook_wrap3(uintptr_t fp_addr, hook_chain3_callback before, hook_chain3_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 3, before, after, udata);
}

static inline hook_err_t fp_hook_wrap4(uintptr_t fp_addr, hook_chain4_callback before, hook_chain4_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 4, before, after, udata);
}

static inline hook_err_t fp_hook_wrap5(uintptr_t fp_addr, hook_chain5_callback before, hook_chain5_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 5, before, after, udata);
}

static inline hook_err_t fp_hook_wrap6(uintptr_t fp_addr, hook_chain6_callback before, hook_chain6_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 6, before, after, udata);
}

static inline hook_err_t fp_hook_wrap7(uintptr_t fp_addr, hook_chain7_callback before, hook_chain7_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 7, before, after, udata);
}

static inline hook_err_t fp_hook_wrap8(uintptr_t fp_addr, hook_chain8_callback before, hook_chain8_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 8, before, after, udata);
}

static inline hook_err_t fp_hook_wrap9(uintptr_t fp_addr, hook_chain9_callback before, hook_chain9_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 9, before, after, udata);
}

static inline hook_err_t fp_hook_wrap10(uintptr_t fp_addr, hook_chain10_callback before, hook_chain10_callback after,
                                        void *udata)
{
    return fp_hook_wrap(fp_addr, 10, before, after, udata);
}

static inline hook_err_t fp_hook_wrap11(uintptr_t fp_addr, hook_chain11_callback before, hook_chain11_callback after,
                                        void *udata)
{
    return fp_hook_wrap(fp_addr, 11, before, after, udata);
}

static inline hook_err_t fp_hook_wrap12(uintptr_t fp_addr, hook_chain12_callback before, hook_chain12_callback after,
                                        void *udata)
{
    return fp_hook_wrap(fp_addr, 12, before, after, udata);
}

#endif
