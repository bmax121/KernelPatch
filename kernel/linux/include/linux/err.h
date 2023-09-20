#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H

#include <compiler.h>

#define MAX_ERRNO 4095

#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

#endif