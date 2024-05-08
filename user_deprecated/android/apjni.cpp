/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <jni.h>
#include <android/log.h>
#include <cstring>

#include "../supercall.h"

#define LOG_TAG "APatchNative"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static void fillIntArray(JNIEnv *env, jobject list, int *data, int count)
{
    auto cls = env->GetObjectClass(list);
    auto add = env->GetMethodID(cls, "add", "(Ljava/lang/Object;)Z");
    auto integerCls = env->FindClass("java/lang/Integer");
    auto constructor = env->GetMethodID(integerCls, "<init>", "(I)V");
    for (int i = 0; i < count; ++i) {
        auto integer = env->NewObject(integerCls, constructor, data[i]);
        env->CallBooleanMethod(list, add, integer);
    }
}

static void addIntToList(JNIEnv *env, jobject list, int ele)
{
    auto cls = env->GetObjectClass(list);
    auto add = env->GetMethodID(cls, "add", "(Ljava/lang/Object;)Z");
    auto integerCls = env->FindClass("java/lang/Integer");
    auto constructor = env->GetMethodID(integerCls, "<init>", "(I)V");
    auto integer = env->NewObject(integerCls, constructor, ele);
    env->CallBooleanMethod(list, add, integer);
}

static int getListSize(JNIEnv *env, jobject list)
{
    auto cls = env->GetObjectClass(list);
    auto size = env->GetMethodID(cls, "size", "()I");
    return env->CallIntMethod(list, size);
}

extern "C" JNIEXPORT jboolean JNICALL Java_me_bmax_apatch_Natives_nativeReady(JNIEnv *env, jclass clz, jstring superKey)
{
    if (!superKey) return -EINVAL;
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    bool rc = sc_ready(skey);
    env->ReleaseStringUTFChars(superKey, skey);
    return rc;
}

extern "C" JNIEXPORT jint JNICALL Java_me_bmax_apatch_Natives_nativeKernelPatchVersion(JNIEnv *env, jclass clz,
                                                                                       jstring superKey)
{
    if (!superKey) return -EINVAL;
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    uint32_t version = sc_kp_ver(skey);
    env->ReleaseStringUTFChars(superKey, skey);
    return version;
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeSu(JNIEnv *env, jclass clz, jstring superKey,
                                                                        jint to_uid, jstring scontext)
{
    if (!superKey) return -EINVAL;
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *sctx = 0;
    if (scontext) sctx = env->GetStringUTFChars(scontext, NULL);
    struct su_profile profile = { 0 };
    profile.uid = getuid();
    profile.to_uid = (uid_t)to_uid;
    if (sctx) strncpy(profile.scontext, sctx, sizeof(profile.scontext) - 1);
    long rc = sc_su(skey, &profile);
    if (rc < 0) LOGE("nativeSu error: %ld\n", rc);
    env->ReleaseStringUTFChars(superKey, skey);
    if (sctx) env->ReleaseStringUTFChars(scontext, sctx);
    return rc;
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeThreadSu(JNIEnv *env, jclass clz, jstring superKey,
                                                                              jint tid, jint to_uid, jstring scontext)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *sctx = 0;
    if (scontext) sctx = env->GetStringUTFChars(scontext, NULL);
    struct su_profile profile = { 0 };
    profile.uid = getuid();
    profile.to_uid = (uid_t)to_uid;
    if (sctx) strncpy(profile.scontext, sctx, sizeof(profile.scontext) - 1);
    long rc = sc_su_task(skey, tid, &profile);
    env->ReleaseStringUTFChars(superKey, skey);
    env->ReleaseStringUTFChars(scontext, sctx);
    return rc;
}

extern "C" JNIEXPORT jint JNICALL Java_me_bmax_apatch_Natives_nativeSuNums(JNIEnv *env, jclass clz, jstring superKey)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    long rc = sc_su_uid_nums(skey);
    env->ReleaseStringUTFChars(superKey, skey);
    return rc;
}

extern "C" JNIEXPORT jintArray JNICALL Java_me_bmax_apatch_Natives_nativeSuUids(JNIEnv *env, jclass clz,
                                                                                jstring superKey)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    int num = sc_su_uid_nums(skey);
    int uids[num];
    long n = sc_su_allow_uids(skey, (uid_t *)uids, num);
    if (n > 0) {
        jintArray array = env->NewIntArray(num);
        env->SetIntArrayRegion(array, 0, n, uids);
        return array;
    }
    env->ReleaseStringUTFChars(superKey, skey);
    return env->NewIntArray(0);
}

extern "C" JNIEXPORT jobject JNICALL Java_me_bmax_apatch_Natives_nativeSuProfile(JNIEnv *env, jclass clz,
                                                                                 jstring superKey, jint uid)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    struct su_profile profile = { 0 };
    long rc = sc_su_uid_profile(skey, (uid_t)uid, &profile);
    if (rc < 0) {
        LOGE("nativeSuProfile error: %ld\n", rc);
        env->ReleaseStringUTFChars(superKey, skey);
        return nullptr;
    }
    jclass cls = env->FindClass("me/bmax/apatch/Natives$Profile");
    jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
    jfieldID uidField = env->GetFieldID(cls, "uid", "I");
    jfieldID toUidField = env->GetFieldID(cls, "toUid", "I");
    jfieldID scontextFild = env->GetFieldID(cls, "scontext", "Ljava/lang/String;");

    jobject obj = env->NewObject(cls, constructor);
    env->SetIntField(obj, uidField, profile.uid);
    env->SetIntField(obj, toUidField, profile.to_uid);
    env->SetObjectField(obj, scontextFild, env->NewStringUTF(profile.scontext));

    return obj;
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeLoadKernelPatchModule(JNIEnv *env, jclass clz,
                                                                                           jstring superKey,
                                                                                           jstring modulePath,
                                                                                           jstring jargs)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *path = env->GetStringUTFChars(modulePath, NULL);
    const char *args = env->GetStringUTFChars(jargs, NULL);
    long rc = sc_kpm_load(skey, path, args, 0);
    if (rc < 0) LOGE("nativeLoadKernelPatchModule error: %ld\n", rc);
    env->ReleaseStringUTFChars(superKey, skey);
    env->ReleaseStringUTFChars(modulePath, path);
    env->ReleaseStringUTFChars(jargs, args);
    return rc;
}

extern "C" JNIEXPORT jobject JNICALL Java_me_bmax_apatch_Natives_nativeControlKernelPatchModule(JNIEnv *env, jclass clz,
                                                                                                jstring superKey,
                                                                                                jstring modName,
                                                                                                jstring jctlargs)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *name = env->GetStringUTFChars(modName, NULL);
    const char *ctlargs = env->GetStringUTFChars(jctlargs, NULL);

    char buf[4096] = { '\0' };
    long rc = sc_kpm_control(skey, name, ctlargs, buf, sizeof(buf));
    if (rc < 0) LOGE("nativeControlKernelPatchModule error: %ld\n", rc);

    jclass cls = env->FindClass("me/bmax/apatch/Natives$KPMCtlRes");
    jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
    jfieldID rcField = env->GetFieldID(cls, "rc", "J");
    jfieldID outMsg = env->GetFieldID(cls, "outMsg", "Ljava/lang/String;");

    jobject obj = env->NewObject(cls, constructor);
    env->SetLongField(obj, rcField, rc);
    env->SetObjectField(obj, outMsg, env->NewStringUTF(buf));

    env->ReleaseStringUTFChars(superKey, skey);
    env->ReleaseStringUTFChars(modName, name);
    env->ReleaseStringUTFChars(jctlargs, ctlargs);
    return obj;
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeUnloadKernelPatchModule(JNIEnv *env, jclass clz,
                                                                                             jstring superKey,
                                                                                             jstring modName)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *name = env->GetStringUTFChars(modName, NULL);
    long rc = sc_kpm_unload(skey, name, 0);
    if (rc < 0) LOGE("nativeUnloadKernelPatchModule error: %ld\n", rc);
    env->ReleaseStringUTFChars(superKey, skey);
    env->ReleaseStringUTFChars(modName, name);
    return rc;
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeKernelPatchModuleNum(JNIEnv *env, jclass clz,
                                                                                          jstring superKey)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    long rc = sc_kpm_nums(skey);
    if (rc < 0) LOGE("nativeKernelPatchModuleNum error: %ld\n", rc);

    env->ReleaseStringUTFChars(superKey, skey);
    return rc;
}

extern "C" JNIEXPORT jstring JNICALL Java_me_bmax_apatch_Natives_nativeKernelPatchModuleList(JNIEnv *env, jclass clz,
                                                                                             jstring superKey)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    long rc = sc_kpm_nums(skey);
    char buf[4096] = { '\0' };
    rc = sc_kpm_list(skey, buf, sizeof(buf));
    if (rc < 0) LOGE("nativeKernelPatchModuleList error: %ld\n", rc);

    env->ReleaseStringUTFChars(superKey, skey);
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jstring JNICALL Java_me_bmax_apatch_Natives_nativeKernelPatchModuleInfo(JNIEnv *env, jclass clz,
                                                                                             jstring superKey,
                                                                                             jstring modName)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *name = env->GetStringUTFChars(modName, NULL);
    char buf[1024] = { '\0' };
    long rc = sc_kpm_info(skey, name, buf, sizeof(buf));
    if (rc < 0) LOGE("nativeKernelPatchModuleInfo error: %ld\n", rc);
    env->ReleaseStringUTFChars(superKey, skey);
    env->ReleaseStringUTFChars(modName, name);
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeGrantSu(JNIEnv *env, jclass clz, jstring superKey,
                                                                             jint uid, jint to_uid, jstring scontext)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *sctx = env->GetStringUTFChars(scontext, NULL);
    struct su_profile profile = { 0 };
    profile.uid = uid;
    profile.to_uid = to_uid;
    if (sctx) strncpy(profile.scontext, sctx, sizeof(profile.scontext) - 1);
    long rc = sc_su_grant_uid(skey, uid, &profile);
    env->ReleaseStringUTFChars(superKey, skey);
    env->ReleaseStringUTFChars(scontext, sctx);
    return rc;
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeRevokeSu(JNIEnv *env, jclass clz, jstring superKey,
                                                                              jint uid)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    long rc = sc_su_revoke_uid(skey, (uid_t)uid);
    env->ReleaseStringUTFChars(superKey, skey);
    return rc;
}

extern "C" JNIEXPORT jstring JNICALL Java_me_bmax_apatch_Natives_nativeSuPath(JNIEnv *env, jclass clz, jstring superKey)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    char buf[SU_PATH_MAX_LEN] = { '\0' };
    long rc = sc_su_get_path(skey, buf, sizeof(buf));
    env->ReleaseStringUTFChars(superKey, skey);
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jboolean JNICALL Java_me_bmax_apatch_Natives_nativeResetSuPath(JNIEnv *env, jclass clz,
                                                                                    jstring superKey, jstring jpath)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *path = env->GetStringUTFChars(jpath, NULL);
    long rc = sc_su_reset_path(skey, path);
    env->ReleaseStringUTFChars(superKey, skey);
    env->ReleaseStringUTFChars(jpath, path);
    return rc == 0;
}
