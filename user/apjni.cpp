#include <jni.h>
#include <android/log.h>
#include <cstring>

#include "supercall.h"

#define LOG_TAG "APatchNative"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

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
    int version = sc_kp_version(skey);
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
    long rc = sc_su(skey, (uid_t)to_uid, sctx);
    env->ReleaseStringUTFChars(superKey, skey);
    if (sctx) env->ReleaseStringUTFChars(scontext, sctx);
    return rc;
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeThreadSu(JNIEnv *env, jclass clz, jstring superKey,
                                                                              jint tid, jint to_uid, jstring scontext)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *sctx = env->GetStringUTFChars(scontext, NULL);
    long rc = sc_su_task(skey, (uid_t)tid, (uid_t)to_uid, sctx);
    env->ReleaseStringUTFChars(superKey, skey);
    env->ReleaseStringUTFChars(scontext, sctx);
    return rc;
}

extern "C" JNIEXPORT jstring JNICALL Java_me_bmax_apatch_Natives_nativeListSu(JNIEnv *env, jclass clz, jstring superKey)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    char buf[1024] = { '\0' };
    long rc = sc_su_list_allow_uids(skey, buf, sizeof(buf));
    env->ReleaseStringUTFChars(superKey, skey);
    jstring result = env->NewStringUTF(buf);
    return result;
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeLoadKernelPatchModule(JNIEnv *env, jclass clz,
                                                                                           jstring superKey,
                                                                                           jstring modulePath,
                                                                                           jstring jargs)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *path = env->GetStringUTFChars(modulePath, NULL);
    const char *args = env->GetStringUTFChars(jargs, NULL);

    long rc = sc_kpm_load(skey, path, args);
    env->ReleaseStringUTFChars(superKey, skey);
    env->ReleaseStringUTFChars(modulePath, path);
    env->ReleaseStringUTFChars(jargs, args);

    return rc;
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeUnloadKernelPatchModule(JNIEnv *env, jclass clz,
                                                                                             jstring superKey,
                                                                                             jstring modName)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *name = env->GetStringUTFChars(modName, NULL);
    long rc = sc_kpm_unload(skey, name);
    env->ReleaseStringUTFChars(superKey, skey);
    env->ReleaseStringUTFChars(modName, name);
    return rc;
}

extern "C" JNIEXPORT jlong JNICALL Java_me_bmax_apatch_Natives_nativeGrantSu(JNIEnv *env, jclass clz, jstring superKey,
                                                                             jint uid, jint to_uid, jstring scontext)
{
    const char *skey = env->GetStringUTFChars(superKey, NULL);
    const char *sctx = env->GetStringUTFChars(scontext, NULL);
    long rc = sc_su_grant_uid(skey, (uid_t)uid, (uid_t)to_uid, sctx);
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
