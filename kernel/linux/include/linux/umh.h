#ifndef __LINUX_UMH_H__
#define __LINUX_UMH_H__

#include <ksyms.h>
#include <uapi/asm-generic/errno.h>

#define UMH_NO_WAIT 0x00 /* don't wait at all */
#define UMH_WAIT_EXEC 0x01 /* wait for the exec, but not the process */
#define UMH_WAIT_PROC 0x02 /* wait for the process to complete */
#define UMH_KILLABLE 0x04 /* wait for EXEC/PROC killable */
#define UMH_FREEZABLE 0x08 /* wait for EXEC/PROC freezable */

extern int kfunc_def(call_usermodehelper)(const char *path, char **argv, char **envp, int wait);

static inline int call_usermodehelper(const char *path, char **argv, char **envp, int wait)
{
    kfunc_call(call_usermodehelper, path, argv, envp, wait);
    kfunc_not_found();
    return -EFAULT;
}

#endif