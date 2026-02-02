
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define PAGE_SIZE_DEFAULT 4096
struct boot_img_hdr {
    uint8_t magic[8];           // "ANDROID!"
    uint32_t kernel_size;
    uint32_t kernel_addr;     //when it come to V3 ,it should be ramdisk_size
    uint32_t ramdisk_size;
    uint32_t ramdisk_addr;
    uint32_t second_size;
    uint32_t second_addr;
    uint32_t tags_addr;
    uint32_t page_size;         // 4096
    uint32_t unused[2];
    uint8_t name[16];
    uint8_t cmdline[512];
    uint32_t id[8];
	uint8_t extra_cmdline[1024];     // command
    
    // v2 
    uint32_t recovery_dtbo_size;     
    uint64_t recovery_dtbo_offset;   
    uint32_t header_size;            
    
    // v3 
    uint32_t dtb_size;               
    uint64_t dtb_addr;               
};
struct kernel_hdr {
	uint32_t code0;      // Executable code
    uint32_t code1;      // Executable code
    uint64_t text_offset; // Image load offset, little endian
    uint64_t image_size;  // Effective Image size, little endian
    uint64_t flags;       // kernel flags, little endian
    uint64_t res2;        // reserved
    uint64_t res3;        // reserved
    uint64_t res4;        // reserved
    uint32_t magic;       // Magic number, "ARM\x64"
    uint32_t res5;        // reserved
	
};

typedef struct {
     uint8_t magic[8];
} compress_head;


int repack_bootimg(const char *orig_boot_path, 
                        const char *new_kernel_path, 
                        const char *out_boot_path);
int extract_kernel(const char *bootimg_path);

int detect_compress_method(compress_head data);