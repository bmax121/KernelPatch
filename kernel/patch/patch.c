#include "patch.h"

#include <log.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>
#include <accctl.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <syscall.h>
#include <module.h>

int linux_sybmol_len_init();
int linux_misc_symbol_init();
int linux_libs_symbol_init();

int resolve_struct();
int task_observer();
int bypass_kcfi();

void before_panic(hook_fargs12_t *args, void *udata)
{
    printk("==== Start KernelPatch for Kernel panic ====\n");

    const char *log = get_boot_log();
    char buf[1024];
    int off = 0;
    char c;
    for (int i = 0; (c = log[i]); i++) {
        if (c == '\n') {
            buf[off++] = c;
            buf[off] = '\0';

            printk("KP %s", buf);
            off = 0;
        } else {
            buf[off++] = log[i];
        }
    }

    printk("==== End KernelPatch for Kernel panic ====\n");
}

static void before_kernel_init(hook_fargs4_t *args, void *udata)
{
    int err = 0;
    log_boot("entering kernel init ...\n");

    if ((err = linux_sybmol_len_init())) goto out;
    if ((err = linux_libs_symbol_init())) goto out;
    if ((err = linux_misc_symbol_init())) goto out;

    if ((err = syscall_init())) goto out;
    if ((err = resolve_struct())) goto out;
    if ((err = bypass_kcfi())) goto out;
    if ((err = task_observer())) goto out;
    if ((err = selinux_hook_install())) goto out;
    if ((err = module_init())) goto out;
    if ((err = supercall_install())) goto out;

#ifdef ANDROID
    if ((err = kpuserd_init())) goto out;
    if ((err = su_compat_init())) goto out;
#endif

out:
    return;
}

static void after_kernel_init(hook_fargs4_t *args, void *udata)
{
    log_boot("exiting kernel init ...\n");
}

int patch()
{
    int rc = 0;

    unsigned long panic_addr = kallsyms_lookup_name("panic");
    if (!panic_addr) {
        log_boot("no symbol panic\n");
        rc = -ENOENT;
        goto out;
    } else {
        hook_err_t err = hook_wrap12((void *)panic_addr, before_panic, 0, 0);
        if (err) {
            log_boot("hook panic: %llx, error: %d\n", panic_addr, rc);
            rc = err;
            goto out;
        }
    }

    // kernel_init or rest_init
    unsigned long init_addr = kallsyms_lookup_name("rest_init");
    if (!init_addr) {
        init_addr = kallsyms_lookup_name("kernel_init");
    }
    if (!init_addr) {
        log_boot("no symbol rest_init or kernel_init\n");
        rc = -ENOENT;
        goto out;
    } else {
        hook_err_t err = hook_wrap4((void *)init_addr, before_kernel_init, after_kernel_init, 0);
        if (err) {
            log_boot("hook kernel init: %llx, error: %d\n", init_addr, err);
            rc = err;
            goto out;
        }
    }

out:
    return rc;
}
