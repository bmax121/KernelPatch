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

#define SUPERCALL_LOAD_KPM 0x1010
#define SUPERCALL_UNLOAD_KPM 0x1011
#define SUPERCALL_KPM_NUMS 0x1012
#define SUPERCALL_KPM_INFO 0x1013
#define SUPERCALL_SU 0x1020
#define SUPERCALL_THREAD_SU 0x1021
#define SUPERCALL_THREAD_UNSU 0x1022

#define SUPERCALL_KEY_MAX_LEN 64
#define SUPERCALL_SCONTEXT_LEN 64

#ifdef ANDROID
#define SUPERCALL_GRANT_SU 0x1100
#define SUPERCALL_REVOKE_SU 0x1101
#define SUPERCALL_SU_ALLOW_NUM 0x1102
#define SUPERCALL_LIST_SU_ALLOW 0x1103
#define SUPERCALL_SU_RESET_PATH 0x1104
#define SUPERCALL_SU_GET_PATH 0x1105

#define SUPERCALL_SU_ALLOW_UID_MAX 32
#define SUPERCALL_SU_PATH_LEN 15
#endif

#define SUPERCALL_MAX 0x1200

#define SUPERCALL_RES_SUCCEED 0

#define SUPERCALL_HELLO_MAGIC 0x1158

#endif
