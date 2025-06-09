#include <ktypes.h>

#include <hook.h>
#include <syscall.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <linux/ptrace.h>
#include <log.h>
#include <preset.h>

static int first_init_execed = 0;

static void before_first_exec()
{
    log_boot("event: %s\n", EXTRA_EVENT_PRE_EXEC_INIT);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2087
// SYSCALL_DEFINE3(execve, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2095
// SYSCALL_DEFINE5(execveat, int, fd, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp, int, flags)
static void before_execve(hook_fargs3_t *args, void *udata)
{
    if (first_init_execed) return;
    first_init_execed = 1;
    before_first_exec();

    log_boot("kernel stack:\n");

    uint64_t arg0 = syscall_argn(args, 0);
    uint64_t arg1 = syscall_argn(args, 1);
    uint64_t arg2 = syscall_argn(args, 2);
    uint64_t nr = (uint64_t)udata;

    unsigned long stack = (unsigned long)get_stack(current);
    uintptr_t addr = (uintptr_t)(thread_size + stack);

    for (uintptr_t i = addr - sizeof(struct pt_regs) - 0x40; i < addr - 32 * 8; i += sizeof(uint32_t)) {
        uintptr_t val0 = *(uintptr_t *)i;
        uintptr_t val1 = *(uintptr_t *)(i + 0x8);
        uintptr_t val2 = *(uintptr_t *)(i + 0x10);

        if ((arg0 == val0) && (val1 == arg1) && (val2 == arg2)) {
            struct pt_regs *regs = (struct pt_regs *)i;
            if (regs->orig_x0 == arg0 && regs->syscallno == nr && regs->regs[8] == nr) {
                pt_regs_offset = addr - i;
                break;
            }
        }
    }
    log_boot("    pt_regs offset: %x\n", pt_regs_offset);
}

static void after_execv(hook_fargs5_t *args, void *udata)
{
    unhook_syscalln(__NR_execve, before_execve, after_execv);
    unhook_syscalln(__NR_execveat, before_execve, after_execv);
}

int resolve_pt_regs()
{
    hook_err_t ret = 0;
    hook_err_t rc = HOOK_NO_ERR;

    rc = hook_syscalln(__NR_execve, 3, before_execve, after_execv, (void *)__NR_execve);
    log_boot("hook __NR_execve rc: %d\n", rc);
    ret |= rc;

    rc = hook_syscalln(__NR_execveat, 5, before_execve, after_execv, (void *)__NR_execveat);
    log_boot("hook __NR_execveat rc: %d\n", rc);
    ret |= rc;

    return rc;
}