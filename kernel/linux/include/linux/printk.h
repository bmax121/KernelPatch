#ifndef __KERNEL_PRINTK__
#define __KERNEL_PRINTK__

#include <ktypes.h>
#include <ksyms.h>
#include <linux/kern_levels.h>

// extern int vprintk_emit(int facility, int level, const struct dev_printk_info *dev_info, const char *fmt, va_list args);
// extern int vprintk(const char *fmt, va_list args);
// extern int printk(const char *fmt, ...);
// extern int printk_deferred(const char *fmt, ...);

extern void kfunc_def(dump_stack_lvl)(const char *log_lvl) __cold;
extern void kfunc_def(dump_stack)(void) __cold;

extern int __printk_ratelimit(const char *func);
#define printk_ratelimit() __printk_ratelimit(__func__)
extern bool printk_timed_ratelimit(unsigned long *caller_jiffies, unsigned int interval_msec);

extern int printk_delay_msec;
extern int dmesg_restrict;

struct ctl_table;

extern int devkmsg_sysctl_set_loglvl(struct ctl_table *table, int write, void *buf, size_t *lenp, loff_t *ppos);

extern void wake_up_klogd(void);

extern void printk_safe_flush(void);
extern void printk_safe_flush_on_panic(void);

extern int kptr_restrict;

#define pr_fmt(fmt) fmt
#define pr_emerg(fmt, ...) printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert(fmt, ...) printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit(fmt, ...) printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...) printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice(fmt, ...) printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_cont(fmt, ...) printk(KERN_CONT fmt, ##__VA_ARGS__)

static inline void dump_stack_lvl(const char *log_lvl)
{
    kfunc_call(dump_stack_lvl, log_lvl);
    kfunc_not_found();
}

static inline void dump_stack(void)
{
    kfunc_direct_call(dump_stack);
}

#endif