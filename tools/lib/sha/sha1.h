#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[SHA1_BLOCK_SIZE];
} SHA1_CTX;

void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t len);
void sha1_final(SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // SHA1_H