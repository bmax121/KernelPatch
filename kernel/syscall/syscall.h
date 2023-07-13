#ifndef _KP_SYSCALL_H_
#define _KP_SYSCALL_H_

#include <asm/ptrace.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>

#define SYS_CALL_MAX_NR 512

#define __MAP0(m, ...)
#define __MAP1(m, t, a, ...) m(t, a)
#define __MAP2(m, t, a, ...) m(t, a), __MAP1(m, __VA_ARGS__)
#define __MAP3(m, t, a, ...) m(t, a), __MAP2(m, __VA_ARGS__)
#define __MAP4(m, t, a, ...) m(t, a), __MAP3(m, __VA_ARGS__)
#define __MAP5(m, t, a, ...) m(t, a), __MAP4(m, __VA_ARGS__)
#define __MAP6(m, t, a, ...) m(t, a), __MAP5(m, __VA_ARGS__)
#define __MAP(n, ...) __MAP##n(__VA_ARGS__)

#define __SC_DECL(t, a) t a
#define __SC_ARGS(t, a) a
#define __SC_EMPTY(t, a) 0

#define ARM64_REGS_TO_ARGS(x, ...)                                                                             \
    __MAP(x, __SC_ARGS, , regs->regs[0], , regs->regs[1], , regs->regs[2], , regs->regs[3], , regs->regs[4], , \
          regs->regs[5])

#define __REGS_ASSIGN0(n, ...)
#define __REGS_ASSIGN1(n, t, a, ...) \
    a = (t)(regs->regs[n - 1]);      \
    __REGS_ASSIGN0(n, __VA_ARGS__)
#define __REGS_ASSIGN2(n, t, a, ...) \
    a = (t)(regs->regs[n - 2]);      \
    __REGS_ASSIGN1(n, __VA_ARGS__)
#define __REGS_ASSIGN3(n, t, a, ...) \
    a = (t)(regs->regs[n - 3]);      \
    __REGS_ASSIGN2(n, __VA_ARGS__)
#define __REGS_ASSIGN4(n, t, a, ...) \
    a = (t)(regs->regs[n - 4]);      \
    __REGS_ASSIGN3(n, __VA_ARGS__)
#define __REGS_ASSIGN5(n, t, a, ...) \
    a = (t)(regs->regs[n - 5]);      \
    __REGS_ASSIGN4(n, __VA_ARGS__)
#define __REGS_ASSIGN6(n, t, a, ...) \
    a = (t)(regs->regs[n - 6]);      \
    __REGS_ASSIGN5(n, __VA_ARGS__)
#define __REGS_ASSIGN(n, ...) __REGS_ASSIGN##n(n, __VA_ARGS__)

#define HOOK_SYSCALL_DEFINE(x, nr, ...)                                                                     \
    static long (*__hook_sys_backup_##nr)(__MAP(x, __SC_DECL, __VA_ARGS__)) = 0;                            \
    static long (*__hook_sys_wrap_backup_##nr)(const struct pt_regs *regs) = 0;                             \
    static long __hook_sys_bridge_##nr(const struct pt_regs *regs, __MAP(x, __SC_DECL, __VA_ARGS__));       \
    static long __hook_sys_common_##nr(const struct pt_regs *regs, __MAP(x, __SC_DECL, __VA_ARGS__));       \
    long __attribute__((__noinline__)) __hook_sys_##nr(__MAP(x, __SC_DECL, __VA_ARGS__))                    \
    {                                                                                                       \
        return __hook_sys_bridge_##nr(0, __MAP(x, __SC_ARGS, __VA_ARGS__));                                 \
    }                                                                                                       \
    long __attribute__((__noinline__)) __hook_sys_wrap_##nr(const struct pt_regs *regs)                     \
    {                                                                                                       \
        return __hook_sys_bridge_##nr(regs, __MAP(x, __SC_EMPTY, __VA_ARGS__));                             \
    }                                                                                                       \
    static long inline __hook_sys_bridge_##nr(const struct pt_regs *regs, __MAP(x, __SC_DECL, __VA_ARGS__)) \
    {                                                                                                       \
        if (regs) { __REGS_ASSIGN(x, __VA_ARGS__); }                                                        \
        return __hook_sys_common_##nr(regs, __MAP(x, __SC_ARGS, __VA_ARGS__));                              \
    }                                                                                                       \
    static long inline __hook_sys_common_##nr(const struct pt_regs *regs, __MAP(x, __SC_DECL, __VA_ARGS__))

#define HOOK_SYSCALL_DEFINE0(nr, ...) HOOK_SYSCALL_DEFINE(0, nr, __VA_ARGS__)
#define HOOK_SYSCALL_DEFINE1(nr, ...) HOOK_SYSCALL_DEFINE(1, nr, __VA_ARGS__)
#define HOOK_SYSCALL_DEFINE2(nr, ...) HOOK_SYSCALL_DEFINE(2, nr, __VA_ARGS__)
#define HOOK_SYSCALL_DEFINE3(nr, ...) HOOK_SYSCALL_DEFINE(3, nr, __VA_ARGS__)
#define HOOK_SYSCALL_DEFINE4(nr, ...) HOOK_SYSCALL_DEFINE(4, nr, __VA_ARGS__)
#define HOOK_SYSCALL_DEFINE5(nr, ...) HOOK_SYSCALL_DEFINE(5, nr, __VA_ARGS__)
#define HOOK_SYSCALL_DEFINE6(nr, ...) HOOK_SYSCALL_DEFINE(6, nr, __VA_ARGS__)

#define __HOOK_SYSCALL_CALL_ORIGIN(nr, ...) \
    (syscall_has_wrapper ? __hook_sys_wrap_backup_##nr(regs) : __hook_sys_backup_##nr(__VA_ARGS__));

#define HOOK_SYSCALL_CALL_ORIGIN(nr, ...) __HOOK_SYSCALL_CALL_ORIGIN(nr, __VA_ARGS__)

#define __HOOK_SYSCALL_INSTALL(nr)                                                                            \
    if (syscall_has_wrapper) {                                                                                \
        replace_syscall_with(nr, (uintptr_t *)&__hook_sys_wrap_backup_##nr, (uintptr_t)__hook_sys_wrap_##nr); \
    } else {                                                                                                  \
        replace_syscall_with(nr, (uintptr_t *)&__hook_sys_backup_##nr, (uintptr_t)__hook_sys_##nr);           \
    }
#define HOOK_SYSCALL_INSTALL(nr) __HOOK_SYSCALL_INSTALL(nr)

#define _ARGS_TO_REGS(regs, idx, val, ...)        \
    do {                                          \
        regs.regs[idx] = val;                     \
        ARGS_TO_REGS(regs, idx + 1, __VA_ARGS__); \
    } while (0)

#define ARGS_TO_REGS(regs, ...) _ARGS_TO_REGS(regs, 0, __VA_ARGS__)

extern bool syscall_has_wrapper;
extern uintptr_t syscall_table_addr;
extern uintptr_t compact_syscall_table_addr;

void replace_syscall_with(long nr, uintptr_t *old, uintptr_t newsc);
void replace_compact_syscall_whit(long nr, uintptr_t *old, uintptr_t newsc);

long raw_syscall0(long nr);
long raw_syscall1(long nr, long arg0);
long raw_syscall2(long nr, long arg0, long arg1);
long raw_syscall3(long nr, long arg0, long arg1, long arg2);
long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3);
long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4);
long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

#define raw_syscall(f) raw_syscall##f

static inline pid_t raw_syscall(getpid)()
{
    return raw_syscall0(__NR_getpid);
}

static inline pid_t raw_syscall(getppid)()
{
    return raw_syscall0(__NR_getppid);
}

static inline pid_t raw_syscall(gettid)()
{
    return raw_syscall0(__NR_gettid);
}

static inline int raw_syscall(setresuid)(uid_t ruid, uid_t euid, uid_t suid)
{
    return raw_syscall3(__NR_getresuid, ruid, euid, suid);
}

static inline uid_t raw_syscall(getuid)()
{
    return raw_syscall0(__NR_getuid);
}

static inline uid_t raw_syscall(geteuid)()
{
    return raw_syscall0(__NR_geteuid);
}

int syscall_init();

#endif