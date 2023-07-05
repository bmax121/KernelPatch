#ifndef _KP_COMMON_H_
#define _KP_COMMON_H_

#include <stdint.h>

#define VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))

typedef enum
{
    little = 0,
    big = 1
} endian_t;

extern uint32_t kver;
extern uint32_t kpver;
extern endian_t endian;

#endif