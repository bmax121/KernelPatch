#ifndef _KPU_ANDROID_KPM_H_
#define _KPU_ANDROID_KPM_H_

#ifdef __cplusplus
extern "C"
{
#endif

    int kpm_main(const char *key, int argc, char **argv);

    int kpm_load(const char *key, const char *path, const char *args);
    int kpm_unload(const char *key, const char *name);
    int kpm_nums(const char *key);
    int kpm_list(const char *key);
    int kpm_info(const char *key, const char *name);

#ifdef __cplusplus
}
#endif

#endif