#ifndef _KP_SUPERCALL_H_
#define _KP_SUPERCALL_H_

static inline long hash_key(const char *key)
{
    long hash = 1000000007;
    for (int i = 0; key[i]; i++) {
        hash = hash * 31 + key[i];
    }
    return hash;
}

// #define __NR_supercall __NR3264_truncate // 45
#define __NR_supercall 45

#define SUPERCALL_HELLO 0x1000
#define SUPERCALL_GET_KERNEL_VERSION 0x1001
#define SUPERCALL_GET_KP_VERSION 0x1002
#define SUPERCALL_LOAD_KPM 0x1003
#define SUPERCALL_UNLOAD_KPM 0x1004
#define SUPERCALL_SU 0x1005
#define SUPERCALL_GRANT_SU 0x1006
#define SUPERCALL_REVOKE_SU 0x1007
#define SUPERCALL_LIST_SU_ALLOW 0x1008
#define SUPERCALL_THREAD_SU 0x1009
#define SUPERCALL_THREAD_UNSU 0x100a

#define SUPERCALL_MAX 0x1100

#define SUPERCALL_RES_SUCCEED 0
#define SUPERCALL_RES_FAILED 1
#define SUPERCALL_RES_NOT_IMPL 2

#define SUPERCALL_HELLO_MAGIC 0x1158

#define SUPERCALL_SCONTEXT_LEN 64
#define SUPERCALL_SU_ALLOW_MAX 32

#endif
