#include <log.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>
#include <accctl.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <syscall.h>
#include <module.h>
#include <predata.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>  

#define LOG_FILE_PATH "/data/adb/ap/log/kernel.log"
#define PANIC_LOG_PATH "/data/adb/ap/log/panic.log"


#ifndef O_WRONLY
#define O_WRONLY  00000001
#endif
#ifndef O_CREAT
#define O_CREAT   00000100
#endif
#ifndef O_TRUNC
#define O_TRUNC   00001000
#endif
#ifndef O_APPEND
#define O_APPEND  00002000
#endif
#ifndef O_DSYNC
#define O_DSYNC   00010000
#endif

#ifndef O_SYNC
#define __O_SYNC	04000000
#define O_SYNC		(__O_SYNC|O_DSYNC)
#endif

/*
 * Keep this list arranged in rough order of priority. Anything listed after
 * KMSG_DUMP_OOPS will not be logged by default unless printk.always_kmsg_dump
 * is passed to the kernel.
 */
enum kmsg_dump_reason {
	KMSG_DUMP_UNDEF,
	KMSG_DUMP_PANIC,
	KMSG_DUMP_OOPS,
	KMSG_DUMP_EMERG,
	KMSG_DUMP_SHUTDOWN,
	KMSG_DUMP_MAX
};

/**
 * struct kmsg_dump_iter - iterator for retrieving kernel messages
 * @cur_seq:	Points to the oldest message to dump
 * @next_seq:	Points after the newest message to dump
 */
struct kmsg_dump_iter {
	u64	cur_seq;
	u64	next_seq;
};

struct kmsg_dumper {
    struct list_head list;
    int registered;
    void (*dump)(struct kmsg_dumper *, enum kmsg_dump_reason);
    enum kmsg_dump_reason max_reason;
    u32 cur_idx;
    u32 next_idx;
    u64 cur_seq;
    u64 next_seq;
    bool active;
    bool sync;
};


typedef int (*kmsg_dump_register_t)(struct kmsg_dumper *dumper);
typedef int (*kmsg_dump_unregister_t)(struct kmsg_dumper *dumper);
typedef void (*kmsg_dump_rewind_t)(void *iter);
typedef bool (*kmsg_dump_get_line_t)(void *iter, bool syslog, char *line, size_t size, size_t *len);


typedef bool (*kmsg_dump_get_buffer_t)(struct kmsg_dump_iter *iter,bool syslog,char *buf,size_t size,size_t *len);

static struct kmsg_dumper kernelpatch_dumper;
static kmsg_dump_register_t kmsg_dump_register_fn = NULL;
static kmsg_dump_unregister_t kmsg_dump_unregister_fn = NULL;
static kmsg_dump_rewind_t kmsg_dump_rewind_fn = NULL;
static kmsg_dump_get_line_t kmsg_dump_get_line_fn = NULL;
static bool kmsg_dump_registered = false;
static kmsg_dump_get_buffer_t   kmsg_dump_get_buffer_fn;

static int simple_snprintf(char *buf, size_t size, const char *fmt, ...)
{
    int i = 0;
    

    if (strstr(fmt, "%llu")) {

        unsigned long long value = 0;
        char num_buf[20];
        char *p = num_buf;
        

        while (i < size - 1) {
            if (*fmt == '%') {
                fmt += 4; 
                while (value > 0 && i < size - 1) {
                    buf[i++] = '0' + (value % 10);
                    value /= 10;
                }
                if (i == 0 && i < size - 1) {
                    buf[i++] = '0';
                }
            } else if (i < size - 1) {
                buf[i++] = *fmt++;
            } else {
                break;
            }
        }
    } else {

        while (*fmt && i < size - 1) {
            buf[i++] = *fmt++;
        }
    }
    
    if (i < size) {
        buf[i] = '\0';
    } else if (size > 0) {
        buf[size - 1] = '\0';
    }
    
    return i;
}


static int get_current_cpu_id(void)
{

    unsigned int (*get_cpu_id_fn)(void);
    
    get_cpu_id_fn = (unsigned int (*)(void))kallsyms_lookup_name("smp_processor_id");
    if (get_cpu_id_fn) {
        return get_cpu_id_fn();
    }
    
    get_cpu_id_fn = (unsigned int (*)(void))kallsyms_lookup_name("raw_smp_processor_id");
    if (get_cpu_id_fn) {
        return get_cpu_id_fn();
    }
    
    return 0; 
}

static const void *kernel_read_file(const char *path, loff_t *len)
{
    set_priv_sel_allow(current, true);
    void *data = 0;

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
        log_boot("open file: %s error: %d\n", path, PTR_ERR(filp));
        goto out;
    }
    *len = vfs_llseek(filp, 0, SEEK_END);
    vfs_llseek(filp, 0, SEEK_SET);
    data = vmalloc(*len);
    loff_t pos = 0;
    kernel_read(filp, data, *len, &pos);
    filp_close(filp, 0);

out:
    set_priv_sel_allow(current, false);
    return data;
}

static loff_t kernel_write_file(const char *path, const void *data, loff_t len, umode_t mode)
{
    loff_t off = 0;
    struct file *(*filp_open_fn)(const char *, int, umode_t);
    int (*filp_close_fn)(struct file *, void *);
    ssize_t (*kernel_write_fn)(struct file *, const void *, size_t, loff_t *);
    
    filp_open_fn = (struct file *(*)(const char *, int, umode_t))kallsyms_lookup_name("filp_open");
    if (!filp_open_fn) return -1;
    
    filp_close_fn = (int (*)(struct file *, void *))kallsyms_lookup_name("filp_close");
    if (!filp_close_fn) return -1;
    
    kernel_write_fn = (ssize_t (*)(struct file *, const void *, size_t, loff_t *))kallsyms_lookup_name("kernel_write");
    if (!kernel_write_fn) return -1;

    typedef int (*vfs_fsync_t)(struct file *, loff_t, loff_t, int); 
    static vfs_fsync_t vfs_fsync_fn; 
    vfs_fsync_fn = (vfs_fsync_t)kallsyms_lookup_name("vfs_fsync");
    if (!vfs_fsync_fn) return -1;

    struct file *fp = filp_open_fn(path, O_SYNC | O_CREAT | O_TRUNC, mode);
    if (!fp || IS_ERR(fp)) {
        return -1;
    }
    
    kernel_write_fn(fp, data, len, &off);
    vfs_fsync_fn(fp, 0, 0x7fffffffffffffffLL, 0);
    filp_close_fn(fp, 0);
    
    return off;
}


static int append_to_file(const char *path, const char *data, size_t len)
{
    struct file *(*filp_open_fn)(const char *, int, umode_t);
    int (*filp_close_fn)(struct file *, void *);
    ssize_t (*kernel_write_fn)(struct file *, const void *, size_t, loff_t *);
    
    filp_open_fn = (struct file *(*)(const char *, int, umode_t))kallsyms_lookup_name("filp_open");
    if (!filp_open_fn) return -1;
    
    filp_close_fn = (int (*)(struct file *, void *))kallsyms_lookup_name("filp_close");
    if (!filp_close_fn) return -1;
    
    kernel_write_fn = (ssize_t (*)(struct file *, const void *, size_t, loff_t *))kallsyms_lookup_name("kernel_write");
    if (!kernel_write_fn) return -1;
    
    struct file *fp = filp_open_fn(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (!fp || IS_ERR(fp)) {
        return -1;
    }
    
    loff_t pos = 0;
    kernel_write_fn(fp, data, len, &pos);
    filp_close_fn(fp, 0);
    
    return 0;
}

void print_bootlog()
{
    const char *log = get_boot_log();
    char buf[1024];
    int off = 0;
    char c;
    for (int i = 0; (c = log[i]); i++) {
        if (c == '\n') {
            buf[off++] = c;
            buf[off] = '\0';

            printk("KP %s", buf);
            off = 0;
        } else {
            buf[off++] = log[i];
        }
    }
}

static void save_via_kmsg_dump(void)
{
    if (!kmsg_dump_rewind_fn || !kmsg_dump_get_line_fn) {
        return;
    }

    void *(*kmalloc_fn)(size_t, unsigned int) = (void *(*)(size_t, unsigned int))kallsyms_lookup_name("kmalloc");
    void (*kfree_fn)(const void *) = (void (*)(const void *))kallsyms_lookup_name("kfree");
    
    if (!kmalloc_fn || !kfree_fn) {
        return;
    }
    

    void *iter = kmalloc_fn(64, 0x20u); // GFP_ATOMIC
    if (!iter) {
        return;
    }
    
    char line[1024];
    size_t len;
    

    kmsg_dump_rewind_fn(iter);
    

    while (kmsg_dump_get_line_fn(iter, true, line, sizeof(line), &len)) {
        if (len > 0) {
            append_to_file(PANIC_LOG_PATH, line, len);
        }
    }
    
    kfree_fn(iter);
}

static void kernelpatch_dump_handler(struct kmsg_dumper *dumper, enum kmsg_dump_reason reason)
{
    printk("KernelPatch: kmsg_dump handler called (reason: %d)\n", reason);
    

    char timestamp[64];
    unsigned long long (*ktime_get_real_seconds_fn)(void) = (unsigned long long (*)(void))kallsyms_lookup_name("ktime_get_real_seconds");
    
    if (ktime_get_real_seconds_fn) {
        unsigned long long ts = ktime_get_real_seconds_fn();
        char ts_str[20];
        char *p = ts_str;
        unsigned long long tmp = ts;
        

        do {
            *p++ = '0' + (tmp % 10);
            tmp /= 10;
        } while (tmp);
        *p = '\0';
        

        int len = p - ts_str;
        for (int i = 0; i < len / 2; i++) {
            char t = ts_str[i];
            ts_str[i] = ts_str[len - 1 - i];
            ts_str[len - 1 - i] = t;
        }
        

        const char *prefix = "\n=== Panic at ";
        const char *suffix = " ===\n";
        
        char *dest = timestamp;
        while (*prefix && dest < timestamp + sizeof(timestamp) - 1) {
            *dest++ = *prefix++;
        }
        
        p = ts_str;
        while (*p && dest < timestamp + sizeof(timestamp) - 1) {
            *dest++ = *p++;
        }
        
        p = (char *)suffix;
        while (*p && dest < timestamp + sizeof(timestamp) - 1) {
            *dest++ = *p++;
        }
        *dest = '\0';
        
        append_to_file(PANIC_LOG_PATH, timestamp, dest - timestamp);
    } else {

        append_to_file(PANIC_LOG_PATH, "\n=== Kernel Panic ===\n", 22);
    }
    

    save_via_kmsg_dump();
    

    if (current) {
        char info[128];
        unsigned int (*task_pid_nr_fn)(struct task_struct *) = (unsigned int (*)(struct task_struct *))kallsyms_lookup_name("task_pid_nr");
        char *(*get_task_comm_fn)(char *, struct task_struct *) = (char *(*)(char *, struct task_struct *))kallsyms_lookup_name("get_task_comm");
        
        if (task_pid_nr_fn && get_task_comm_fn) {
            char comm[16];
            get_task_comm_fn(comm, current);
            unsigned int pid = task_pid_nr_fn(current);
            int cpu_id = get_current_cpu_id();
            
 
            char *p = info;
            const char *pid_str = "PID: ";
            const char *cpu_str = ", CPU: ";
            const char *comm_str = ", Comm: ";
            const char *newline = "\n";
            

            strcpy(p, pid_str); p += strlen(pid_str);
            
 
            char pid_buf[10];
            char *pid_p = pid_buf;
            unsigned int pid_tmp = pid;
            do {
                *pid_p++ = '0' + (pid_tmp % 10);
                pid_tmp /= 10;
            } while (pid_tmp);
            *pid_p = '\0';
            
  
            int pid_len = pid_p - pid_buf;
            for (int i = 0; i < pid_len / 2; i++) {
                char t = pid_buf[i];
                pid_buf[i] = pid_buf[pid_len - 1 - i];
                pid_buf[pid_len - 1 - i] = t;
            }
            
            strcpy(p, pid_buf); p += pid_len;
            strcpy(p, cpu_str); p += strlen(cpu_str);
            
 
            char cpu_buf[10];
            char *cpu_p = cpu_buf;
            int cpu_tmp = cpu_id;
            do {
                *cpu_p++ = '0' + (cpu_tmp % 10);
                cpu_tmp /= 10;
            } while (cpu_tmp);
            *cpu_p = '\0';
            

            int cpu_len = cpu_p - cpu_buf;
            for (int i = 0; i < cpu_len / 2; i++) {
                char t = cpu_buf[i];
                cpu_buf[i] = cpu_buf[cpu_len - 1 - i];
                cpu_buf[cpu_len - 1 - i] = t;
            }
            
            strcpy(p, cpu_buf); p += cpu_len;
            strcpy(p, comm_str); p += strlen(comm_str);
            strcpy(p, comm); p += strlen(comm);
            strcpy(p, newline); p += strlen(newline);
            *p = '\0';
            
            append_to_file(PANIC_LOG_PATH, info, p - info);
        }
    }
}


static int init_kmsg_dump(void)
{
    kmsg_dump_register_fn = (kmsg_dump_register_t)kallsyms_lookup_name("kmsg_dump_register");
    kmsg_dump_unregister_fn = (kmsg_dump_unregister_t)kallsyms_lookup_name("kmsg_dump_unregister");
    kmsg_dump_rewind_fn = (kmsg_dump_rewind_t)kallsyms_lookup_name("kmsg_dump_rewind");
    kmsg_dump_get_line_fn = (kmsg_dump_get_line_t)kallsyms_lookup_name("kmsg_dump_get_line");
    
    if (!kmsg_dump_register_fn) {
        log_boot("kmsg_dump_register not found\n");
        return -ENOENT;
    }
    
    memset(&kernelpatch_dumper, 0, sizeof(kernelpatch_dumper));
    
    kernelpatch_dumper.dump = kernelpatch_dump_handler;
    kernelpatch_dumper.max_reason = KMSG_DUMP_PANIC;
    

    int ret = kmsg_dump_register_fn(&kernelpatch_dumper);
    if (ret == 0) {
        kmsg_dump_registered = true;
        log_boot("Registered kmsg_dumper successfully\n");
        
        if (kmsg_dump_rewind_fn && kmsg_dump_get_line_fn) {
            log_boot("kmsg_dump API functions found\n");
        }
    } else {
        log_boot("Failed to register kmsg_dumper: %d\n", ret);
    }
    
    return ret;
}

void before_panic(hook_fargs12_t *args, void *udata)
{
    printk("==== KernelPatch: Panic detected ====\n");
    

    void (*console_flush)(void) = (void (*)(void))kallsyms_lookup_name("console_flush_on_panic");
    if (console_flush) {
        console_flush();
    }
    
    
    int (*do_syslog)(int type, char *buf, int len) = (int (*)(int, char *, int))kallsyms_lookup_name("do_syslog");
    printk("KernelPatch: do_syslog addr: %llx\n", do_syslog ? (unsigned long long)do_syslog : 0);
    if (do_syslog) {
        void *(*kmalloc_fn)(size_t, unsigned int) = (void *(*)(size_t, unsigned int))kallsyms_lookup_name("__kmalloc");
        if (!kmalloc_fn) {
            kmalloc_fn = (void *(*)(size_t, unsigned int))kallsyms_lookup_name("__kmalloc_noprof");
        }
        void (*kfree_fn)(const void *) = (void (*)(const void *))kallsyms_lookup_name("kfree");
        printk("KernelPatch: kmalloc addr: %llx, kfree addr: %llx\n",
               kmalloc_fn ? (unsigned long long)kmalloc_fn : 0,
               kfree_fn ? (unsigned long long)kfree_fn : 0);
        if (kmalloc_fn && kfree_fn) {
            if (kver<VERSION(5, 10, 0)) {
                
                char *buf = kmalloc_fn(64 * 1024, 0x20u); // GFP_ATOMIC
                printk("KernelPatch: Allocated buffer at %llx\n", buf ? (unsigned long long)buf : 0);
                if (buf) {
                    int len = do_syslog(3, buf, 64 * 1024);
                    printk("KernelPatch: do_syslog returned %d\n", len);
                    if (len > 0) {
                        kernel_write_file(LOG_FILE_PATH, buf, len, 0644);
                        printk("KernelPatch: Saved %d bytes via do_syslog\n", len);
                    }
                    kfree_fn(buf);
                }
            } else {
                kmsg_dump_rewind_fn =
                    (kmsg_dump_rewind_t)kallsyms_lookup_name("kmsg_dump_rewind");

                kmsg_dump_get_buffer_fn =
                    (kmsg_dump_get_buffer_t)kallsyms_lookup_name("kmsg_dump_get_buffer");

                printk("KernelPatch: kmsg_dump_rewind = %px\n", kmsg_dump_rewind_fn);
                printk("KernelPatch: kmsg_dump_get_buffer = %px\n",
                    kmsg_dump_get_buffer_fn);
                if (kmsg_dump_rewind_fn && kmsg_dump_get_buffer_fn) {
                    
                    struct kmsg_dump_iter iter;
                    char *buf;
                    size_t len;

                    buf = kmalloc_fn(64 * 1024, 0x20u);
                    printk("KernelPatch: Allocated buffer at %px\n", buf);

                    if (!buf)
                        return;

                    memset(&iter, 0, sizeof(iter));

                    /* rewind log buffer */
                    kmsg_dump_rewind_fn(&iter);

                    /* dump all dmesg */
                    while (kmsg_dump_get_buffer_fn(&iter,
                                                true,     /* syslog format */
                                                buf,
                                                64 * 1024,
                                                &len)) {
                        if (len > 0) {
                            printk("KernelPatch: Writing %zu bytes to log file\n", len);
                            kernel_write_file(LOG_FILE_PATH, buf, len, 0644);
                            memset(buf, 0, 64 * 1024);
                            //buf = kernel_read_file(LOG_FILE_PATH, &len);
                            //printk("KernelPatch: Log file size now %zu bytes\n", len);
                        }
                    }

                    kfree_fn(buf);

                    printk("KernelPatch: kmsg_dump finished\n");
                
                }
            }
        }
    }

    print_bootlog();
    
    printk("==== KernelPatch: Done ====\n");
}

void linux_misc_symbol_init();
void linux_libs_symbol_init();

int resolve_struct();
int task_observer();
int bypass_kcfi();
int bypass_selinux();
int resolve_pt_regs();
int supercall_install();
void module_init();
void syscall_init();
int kstorage_init();
int su_compat_init();

#ifdef ANDROID
int android_user_init();
int android_sepolicy_flags_fix();
#endif

static void before_rest_init(hook_fargs4_t *args, void *udata)
{
    int rc = 0;
    log_boot("entering init ...\n");

    rc = init_kmsg_dump();
    log_boot("init_kmsg_dump done: %d\n", rc);
    
    if ((rc = bypass_kcfi())) goto out;
    log_boot("bypass_kcfi done: %d\n", rc);

    if ((rc = resolve_struct())) goto out;
    log_boot("resolve_struct done: %d\n", rc);

    if ((rc = bypass_selinux())) goto out;
    log_boot("bypass_selinux done: %d\n", rc);

    if ((rc = task_observer())) goto out;
    log_boot("task_observer done: %d\n", rc);

    rc = supercall_install();
    log_boot("supercall_install done: %d\n", rc);

    rc = kstorage_init();
    log_boot("kstorage_init done: %d\n", rc);

    rc = su_compat_init();
    log_boot("su_compat_init done: %d\n", rc);

    rc = resolve_pt_regs();
    log_boot("resolve_pt_regs done: %d\n", rc);

#ifdef ANDROID
    rc = android_sepolicy_flags_fix();
    log_boot("android_sepolicy_flags_fix done: %d\n", rc);

    rc = android_user_init();
    log_boot("android_user_init done: %d\n", rc);
#endif

out:
    return;
}

static int extra_event_pre_kernel_init(const patch_extra_item_t *extra, const char *args, const void *data, void *udata)
{
    if (extra->type == EXTRA_TYPE_KPM) {
        if (!strcmp(EXTRA_EVENT_PRE_KERNEL_INIT, extra->event) || !extra->event[0]) {
            int rc = load_module(data, extra->con_size, args, EXTRA_EVENT_PRE_KERNEL_INIT, 0);
            log_boot("load kpm: %s, rc: %d\n", extra->name, rc);
        }
    }
    return 0;
}

static void before_kernel_init(hook_fargs4_t *args, void *udata)
{
    log_boot("event: %s\n", EXTRA_EVENT_PRE_KERNEL_INIT);
    on_each_extra_item(extra_event_pre_kernel_init, 0);
}

static void after_kernel_init(hook_fargs4_t *args, void *udata)
{
    log_boot("event: %s\n", EXTRA_EVENT_POST_KERNEL_INIT);
}

int patch()
{
    linux_libs_symbol_init();
    linux_misc_symbol_init();
    module_init();
    syscall_init();

    hook_err_t rc = 0;

    unsigned long panic_addr = patch_config->panic;
    logkd("panic addr: %llx\n", panic_addr);
    if (panic_addr) {
        rc = hook_wrap12((void *)panic_addr, before_panic, 0, 0);
        log_boot("hook panic rc: %d\n", rc);
    }
    if (rc) return rc;

    // rest_init or cgroup_init
    unsigned long init_addr = patch_config->rest_init;
    if (!init_addr) init_addr = patch_config->cgroup_init;
    if (init_addr) {
        rc = hook_wrap4((void *)init_addr, before_rest_init, 0, (void *)init_addr);
        log_boot("hook rest_init rc: %d\n", rc);
    }
    if (rc) return rc;

    // kernel_init
    unsigned long kernel_init_addr = patch_config->kernel_init;
    if (kernel_init_addr) {
        rc = hook_wrap4((void *)kernel_init_addr, before_kernel_init, after_kernel_init, 0);
        log_boot("hook kernel_init rc: %d\n", rc);
    }

    return rc;
}