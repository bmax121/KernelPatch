/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_TOOL_SECRET_INPUT_H_
#define _KP_TOOL_SECRET_INPUT_H_

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "../kernel/include/kpsecret.h"

/* Read a single key from a caller-supplied pipe/fd; never put the key in argv. */
static inline int kp_read_secret_fd(const char *fd_text, char *buffer, unsigned long capacity)
{
    char *end;
    long fd;
    unsigned long used = 0;
    if (!fd_text || !fd_text[0] || !buffer || capacity < 2) return -EINVAL;
    errno = 0;
    fd = strtol(fd_text, &end, 10);
    if (errno || *end || fd < 0 || fd > 0x7fffffffL) return -EINVAL;
    kp_secret_wipe(buffer, capacity);
    for (;;) {
        unsigned char byte;
        ssize_t count = read((int)fd, &byte, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { int rc = -errno; kp_secret_wipe(buffer, capacity); return rc; }
        if (!count || byte == '\n') break;
        if (!byte || used >= capacity - 1) { kp_secret_wipe(buffer, capacity); return -E2BIG; }
        buffer[used++] = byte;
    }
    if (used && buffer[used - 1] == '\r') buffer[--used] = '\0';
    if (!used) return -EINVAL;
    buffer[used] = '\0';
    return 0;
}

#endif
