#include <log.h>
#include <linux/security.h>
#include <linux/string.h>

void test()
{
    logkd("=== start test ===");

    const char *sctx = "u:r:kernel:s0";

    uint32_t secid = 0;
    int rc = security_secctx_to_secid(sctx, strlen(sctx), &secid);

    logkd("secid: %d, rc: %d\n", secid, rc);

    logkd("=== end test ===");
}