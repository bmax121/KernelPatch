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

#define SUPERCALL_HELLO_ECHO "Hello KernelPatch"

// #define __NR_supercall __NR3264_truncate // 45
#define __NR_supercall 45

#define SUPERCALL_HELLO 0x1000
#define SUPERCALL_KLOG 0x1004

#define SUPERCALL_KP_VERSION 0x1008

#define SUPERCALL_SU 0x1010
#define SUPERCALL_SU_TASK 0x1011 // syscall(__NR_gettid)

#define SUPERCALL_KPM_LOAD 0x1020
#define SUPERCALL_KPM_UNLOAD 0x1021
#define SUPERCALL_KPM_NUMS 0x1022
#define SUPERCALL_KPM_LIST 0x1023
#define SUPERCALL_KPM_INFO 0x1024

#define SUPERCALL_TEST 0x10ff

#define SUPERCALL_KEY_MAX_LEN 0x40
#define SUPERCALL_SCONTEXT_LEN 0x60

#ifdef ANDROID

#define ANDROID_SH_PATH "/system/bin/sh"
#define SU_PATH_MIN_LEN sizeof(ANDROID_SH_PATH)
#define SU_PATH_MAX_LEN 64
#define ANDROID_SU_PATH "/system/bin/kp"
#define APD_PATH "/data/adb/apd"
#define KPATCH_PATH "/data/adb/kpatch"
#define KPATCH_SHADOW_PATH "/system/bin/truncate"

#define SUPERCALL_SU_GRANT_UID 0x1100
#define SUPERCALL_SU_REVOKE_UID 0x1101
#define SUPERCALL_SU_ALLOW_UID_NUM 0x1102
#define SUPERCALL_SU_LIST_ALLOW_UID 0x1103
#define SUPERCALL_SU_GET_PATH 0x1104
#define SUPERCALL_SU_RESET_PATH 0x1105

#endif

#define SUPERCALL_MAX 0x1200

#define SUPERCALL_RES_SUCCEED 0

#define SUPERCALL_HELLO_MAGIC 0x11581158

#endif
