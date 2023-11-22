#ifndef _KP_UTILS_H_
#define _KP_UTILS_H_

#include <compiler.h>
#include <ktypes.h>

int __must_check seq_copy_to_user(void __user *to, const void *from, int n);

#endif