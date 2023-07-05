#ifndef _KP_LOG_H_
#define _KP_LOG_H_

extern void (*printk)(const char *fmt, ...);

// #define logkv(fmt, ...) printk("[+] KP V " fmt, ##__VA_ARGS__)
#define logkv(fmt, ...)

#define logkd(fmt, ...) printk("[+] KP D " fmt, ##__VA_ARGS__)

#define logki(fmt, ...) printk("[+] KP I " fmt, ##__VA_ARGS__)

#define logkw(fmt, ...) printk("[-] KP W " fmt, ##__VA_ARGS__)

#define logke(fmt, ...) printk("[-] KP E " fmt, ##__VA_ARGS__)

#endif