int repack_bootimg(const char *orig_boot_path, 
                        const char *new_kernel_path, 
                        const char *out_boot_path);
int extract_kernel(const char *bootimg_path);