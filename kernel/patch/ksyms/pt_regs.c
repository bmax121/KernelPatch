#include <ktypes.h>

#include <hook.h>
#include <syscall.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <linux/ptrace.h>
#include <log.h>

static int first_init_execed = 0;

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2087
// SYSCALL_DEFINE3(execve, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2095
// SYSCALL_DEFINE5(execveat, int, fd, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp, int, flags)
static void before_execve(hook_fargs5_t *args, void *udata)
{
    if (first_init_execed) return;
    first_init_execed = 1;

    uint64_t arg0 = syscall_argn(args, 0);
    uint64_t arg1 = syscall_argn(args, 1);
    uint64_t arg2 = syscall_argn(args, 2);
    uint64_t nr = (uint64_t)udata;

    unsigned long stack = (unsigned long)get_stack(current);
    uintptr_t addr = (uintptr_t)(thread_size + stack);

    for (uintptr_t i = addr - sizeof(struct pt_regs) - 0x40; i < addr - 31 * 8; i += 8) {
        uintptr_t val0 = *(uintptr_t *)i;
        uintptr_t val1 = *(uintptr_t *)(i + 0x8);
        uintptr_t val2 = *(uintptr_t *)(i + 0x10);

        if ((arg0 == val0) && (val1 == arg1) && (val2 == arg2)) {
            struct pt_regs *regs = (struct pt_regs *)i;
            if (regs->orig_x0 == arg0 && regs->syscallno == nr && regs->regs[8] == nr) {
                pt_regs_offset = addr - i;
                log_boot("pt_regs offset of stack top: %llx\n", pt_regs_offset);
                break;
            }
        }
    }
    if (pt_regs_offset < 0) {
        log_boot("can't resolve pt_regs\n");
    }
}

static void after_execv(hook_fargs5_t *args, void *udata)
{
    inline_unhook_syscall(__NR_execve, before_execve, after_execv);
    inline_unhook_syscall(__NR_execveat, before_execve, after_execv);
}

int resolve_pt_regs()
{
    inline_hook_syscalln(__NR_execve, 3, before_execve, after_execv, (void *)__NR_execve);
    inline_hook_syscalln(__NR_execveat, 5, before_execve, after_execv, (void *)__NR_execveat);
    return 0;
}