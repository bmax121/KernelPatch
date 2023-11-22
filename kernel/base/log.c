#include <stdint.h>

#define BOOT_LOG_SIZE 1024

static char boot_log[BOOT_LOG_SIZE] = { 0 };
static int boot_log_len = 0;
static int boot_log_fin = 0;
