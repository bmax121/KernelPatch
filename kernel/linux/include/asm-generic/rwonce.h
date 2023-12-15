#ifndef __ASM_GENERIC_RWONCE_H
#define __ASM_GENERIC_RWONCE_H

// todo:

#define READ_ONCE(x) (*(const volatile typeof(x) *)&(x))

#define WRITE_ONCE(x, val)                   \
    do {                                     \
        *(volatile typeof(x) *)&(x) = (val); \
    } while (0)

#endif
