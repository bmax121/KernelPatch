#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/unistd.h>

#define NUM_SAMPLES   15
#define NUM_ITERS     200
#define WARMUP_ITERS  100   /* per-sample warmup to stabilize CPU freq */
#define MAX_RETRIES   3
#define THRESH_HIGH   2.2
#define THRESH_MID    1.4
#define VARIANCE_PCT  5     /* MAD must be < 1/N of value */

static inline uint64_t read_cntvct(void) {
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}

static inline long raw_syscall3(long nr, long a0, long a1, long a2) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ __volatile__("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory", "cc");
    return x0;
}

static inline long raw_syscall4(long nr, long a0, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    __asm__ __volatile__("svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
        : "memory", "cc");
    return x0;
}

static void sort_i64(int64_t *arr, int n) {
    for (int i = n - 1; i > 0; i--)
        for (int j = 0; j < i; j++)
            if (arr[j] > arr[j + 1]) {
                int64_t t = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = t;
            }
}

static void collect_timing(int64_t *overhead, int64_t *t_unlinkat,
                           int64_t *t_faccessat, int64_t *t_fstatat,
                           int count, int iters) {
    static const char path[] = "a";
    const long at_fdcwd = -100;
    const long bad_flags = -1;

    for (int s = 0; s < count; s++) {
        /* warmup: run all 3 syscalls to pull CPU out of idle */
        for (int i = 0; i < WARMUP_ITERS; i++) {
            raw_syscall3(__NR_unlinkat,  at_fdcwd, (long)path, bad_flags);
            raw_syscall3(__NR_faccessat, at_fdcwd, (long)path, bad_flags);
            raw_syscall4(__NR_newfstatat, at_fdcwd, (long)path, 0, bad_flags);
        }

        /* timer overhead */
        uint64_t c0 = read_cntvct();
        uint64_t c1 = read_cntvct();
        overhead[s] = (int64_t)(c1 - c0);

        /* unlinkat */
        uint64_t start = read_cntvct();
        for (int i = 0; i < iters; i++)
            raw_syscall3(__NR_unlinkat, at_fdcwd, (long)path, bad_flags);
        uint64_t end = read_cntvct();
        t_unlinkat[s] = (int64_t)(end - start);

        /* faccessat */
        start = read_cntvct();
        for (int i = 0; i < iters; i++)
            raw_syscall3(__NR_faccessat, at_fdcwd, (long)path, bad_flags);
        end = read_cntvct();
        t_faccessat[s] = (int64_t)(end - start);

        /* newfstatat */
        start = read_cntvct();
        for (int i = 0; i < iters; i++)
            raw_syscall4(__NR_newfstatat, at_fdcwd, (long)path, 0, bad_flags);
        end = read_cntvct();
        t_fstatat[s] = (int64_t)(end - start);
    }

    sort_i64(overhead,    count);
    sort_i64(t_unlinkat,  count);
    sort_i64(t_faccessat, count);
    sort_i64(t_fstatat,   count);
}

static int64_t mad(const int64_t *sorted, int n, int64_t center) {
    int64_t diffs[n];
    for (int i = 0; i < n; i++) {
        int64_t d = sorted[i] - center;
        diffs[i] = d < 0 ? -d : d;
    }
    sort_i64(diffs, n);
    return diffs[n / 2];
}

static int run_detection(int attempt) {
    int64_t buf_ov[NUM_SAMPLES], buf_ul[NUM_SAMPLES];
    int64_t buf_fa[NUM_SAMPLES], buf_st[NUM_SAMPLES];

    collect_timing(buf_ov, buf_ul, buf_fa, buf_st, NUM_SAMPLES, NUM_ITERS);

    const int idx = 10; /* p67 of 15 */
    int64_t ov = buf_ov[idx], ul = buf_ul[idx];
    int64_t fa = buf_fa[idx], st = buf_st[idx];

    printf("  [attempt %d] sorted samples (x%d iters):\n", attempt, NUM_ITERS);
    printf("  %-10s %-10s %-10s %-10s\n", "overhead", "unlinkat", "faccessat", "fstatat");
    for (int i = 0; i < NUM_SAMPLES; i++)
        printf("  %-10lld %-10lld %-10lld %-10lld%s\n",
               (long long)buf_ov[i], (long long)buf_ul[i],
               (long long)buf_fa[i], (long long)buf_st[i],
               i == idx ? " <-p67" : "");

    int64_t m_ul = mad(buf_ul, NUM_SAMPLES, ul);
    int64_t m_fa = mad(buf_fa, NUM_SAMPLES, fa);
    int64_t m_st = mad(buf_st, NUM_SAMPLES, st);

    printf("  p67: ov=%lld ul=%lld fa=%lld st=%lld\n",
           (long long)ov, (long long)ul, (long long)fa, (long long)st);
    printf("  MAD: ul=%lld fa=%lld st=%lld\n\n",
           (long long)m_ul, (long long)m_fa, (long long)m_st);

    if (m_ul * VARIANCE_PCT > ul || m_fa * VARIANCE_PCT > fa || m_st * VARIANCE_PCT > st) {
        printf("  [!] variance too high (threshold 1/%d), retrying...\n\n", VARIANCE_PCT);
        return -1; /* retry */
    }

    if (ul <= ov || fa <= ov || st <= ov) {
        printf("  [!] sanity failed: syscall <= overhead, retrying...\n\n");
        return -1;
    }

    double r0 = (double)(fa - ov) / (double)(ul - ov);
    double r1 = (double)(st - ov) / (double)(ul - ov);

    printf("  ratio0 (faccessat/unlinkat) = %.4f\n", r0);
    printf("  ratio1 (fstatat/unlinkat)   = %.4f\n\n", r1);

    if (r0 > THRESH_HIGH && r1 > THRESH_HIGH) {
        printf("[!] Side-Channel Detected: KernelSU Installed (High Latency)\n");
        return 2;
    }
    if (r0 > THRESH_MID && r1 > THRESH_MID) {
        printf("[!] Side-Channel Detected: APatch/KP Installed (Mid Latency)\n");
        return 3;
    }

    printf("[+] No root framework detected\n");
    return 0;
}

int main(void) {
    printf("[*] Syscall timing side-channel detection\n");
    printf("[*] samples=%d  iters=%d  warmup=%d  retries=%d\n\n",
           NUM_SAMPLES, NUM_ITERS, WARMUP_ITERS, MAX_RETRIES);

    for (int i = 0; i < MAX_RETRIES; i++) {
        int rc = run_detection(i + 1);
        if (rc >= 0)
            return rc;
    }

    printf("[!] All %d attempts had too much variance\n", MAX_RETRIES);
    return 1;
}
