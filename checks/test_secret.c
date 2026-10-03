/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host unit tests for credential handling: volatile erasure, constant-time
 * comparison, and fd-based secret input (never argv).
 * Build:
 *   gcc -O2 -Wall -Wextra -o /tmp/test_secret checks/test_secret.c && /tmp/test_secret
 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../kernel/include/kpsecret.h"
#include "../tools/secret_input.h"

static void test_wipe_and_compare(void)
{
    char buf[64];
    memset(buf, 0x55, sizeof(buf));
    kp_secret_wipe(buf, sizeof(buf));
    for (unsigned int i = 0; i < sizeof(buf); i++) assert(!buf[i]);

    assert(kp_secret_equal("abc", "abc", 3));
    assert(!kp_secret_equal("abc", "abd", 3));
    assert(!kp_secret_equal("abc", "ab", 2) == 0);

    assert(kp_secret_length(NULL, 64) == 64);
    assert(kp_secret_length("abc", 2) == 2);
    assert(kp_secret_length("abc", 8) == 3);
}

static void test_fd_input(void)
{
    const char *cases[] = { "valid-key\n", "windows-key\r\n", "", "\n", "too-long" };
    const int expected[] = { 0, 0, -EINVAL, -EINVAL, -E2BIG };
    char buf[64];

    for (unsigned int i = 0; i < 5; i++) {
        int fds[2];
        char fdtext[32];
        unsigned long cap = i == 4 ? 4 : sizeof(buf);
        assert(!pipe(fds));
        assert(write(fds[1], cases[i], strlen(cases[i])) == (ssize_t)strlen(cases[i]));
        close(fds[1]);
        snprintf(fdtext, sizeof(fdtext), "%d", fds[0]);
        assert(kp_read_secret_fd(fdtext, buf, cap) == expected[i]);
        if (i == 0) assert(!strcmp(buf, "valid-key"));
        if (i == 1) assert(!strcmp(buf, "windows-key"));
        /* Oversized input must leave the buffer fully wiped, not partial. */
        if (i == 4) for (unsigned long j = 0; j < cap; j++) assert(!buf[j]);
        close(fds[0]);
    }

    /* Malformed fd arguments are rejected. */
    assert(kp_read_secret_fd("-1", buf, sizeof(buf)) == -EINVAL);
    assert(kp_read_secret_fd("4abc", buf, sizeof(buf)) == -EINVAL);
    assert(kp_read_secret_fd("", buf, sizeof(buf)) == -EINVAL);
}

int main(void)
{
    test_wipe_and_compare();
    test_fd_input();
    puts("PASS: credential erasure, constant-time compare, fd secret input");
    return 0;
}
