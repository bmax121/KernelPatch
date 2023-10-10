#include "libkp.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/capability.h>

#include "version"

uint32_t get_version()
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return version_code;
}

long su_fork(const char *key, const char *sctx)
{
    long ret = 0;
#if 0
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);
    fprintf(stdout, "before resuid: %ud, %ud, %ud, resgid: %ud, %ud, %ud\n", ruid, euid, suid, rgid, egid, sgid);

    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data;
    cap_header.pid = getpid();
    cap_header.version = _LINUX_CAPABILITY_VERSION_3;
    ret = syscall(SYS_capget, &cap_header, &cap_data);
    fprintf(stdout, "before capabilities: ret: %ld 0x%x, 0x%x, 0x%x\n", ret, cap_data.effective, cap_data.permitted,
            cap_data.inheritable);
#endif
    ret = sc_su(key, sctx);
#if 0
    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);
    fprintf(stdout, "after resuid: %ud, %ud, %ud, resgid: %ud, %ud, %ud\n", ruid, euid, suid, rgid, egid, sgid);

    cap_header.pid = getpid();
    cap_header.version = _LINUX_CAPABILITY_VERSION_3;
    ret = syscall(SYS_capget, &cap_header, &cap_data);
    fprintf(stdout, "after capabilities: ret: %ld, 0x%x, %x, %x\n", ret, cap_data.effective, cap_data.permitted,
            cap_data.inheritable);
#endif
    // todo: shell path
    if (!ret)
        execlp("/system/bin/sh", "sh", NULL);
    return ret;
}
