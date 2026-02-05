#include <stdint.h>
#include <string.h>
#include "sha1.h"


#define ROTL32(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void sha1_transform(uint32_t state[5], const uint8_t buffer[SHA1_BLOCK_SIZE]) {
    uint32_t a, b, c, d, e, t, W[80];
    int i;


    for (i = 0; i < 16; ++i) {
        W[i] = ((uint32_t)buffer[i * 4] << 24) | ((uint32_t)buffer[i * 4 + 1] << 16) |
               ((uint32_t)buffer[i * 4 + 2] << 8) | ((uint32_t)buffer[i * 4 + 3]);
    }


    for (; i < 80; ++i) {
        W[i] = ROTL32(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];


    for (i = 0; i < 80; ++i) {
        if (i < 20)
            t = ((b & c) | ((~b) & d)) + 0x5A827999;
        else if (i < 40)
            t = (b ^ c ^ d) + 0x6ED9EBA1;
        else if (i < 60)
            t = ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDC;
        else
            t = (b ^ c ^ d) + 0xCA62C1D6;

        t += ROTL32(a, 5) + e + W[i];
        e = d; d = c; c = ROTL32(b, 30); b = a; a = t;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void sha1_init(SHA1_CTX *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i, j;
    j = (size_t)((ctx->count >> 3) & 63); 
    ctx->count += (uint64_t)len << 3;   

    if ((j + len) > 63) {
        i = 64 - j;
        memcpy(&ctx->buffer[j], data, i);
        sha1_transform(ctx->state, ctx->buffer);
        for (; i + 63 < len; i += 64) {
            sha1_transform(ctx->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buffer[j], &data[i], len - i);
}

void sha1_final(SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]) {
    uint8_t final_count[8];
    uint8_t c;

    for (int i = 0; i < 8; i++) {
        final_count[i] = (uint8_t)((ctx->count >> ((7 - i) * 8)) & 255);
    }


    c = 0x80;
    sha1_update(ctx, &c, 1);


    while ((size_t)((ctx->count >> 3) & 63) != 56) {
        c = 0x00;
        sha1_update(ctx, &c, 1);
    }

    sha1_update(ctx, final_count, 8);

    for (int i = 0; i < 5; i++) {
        digest[i * 4]     = (uint8_t)((ctx->state[i] >> 24) & 255);
        digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 255);
        digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 255);
        digest[i * 4 + 3] = (uint8_t)((ctx->state[i]) & 255);
    }
}