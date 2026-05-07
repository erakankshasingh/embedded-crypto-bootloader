/*
 * sha256.c — SHA-256 Implementation
 *
 * Pure C implementation of SHA-256.
 * No external dependencies. No heap allocation.
 * Suitable for ARM Cortex-M embedded targets.
 *
 * References:
 *   FIPS 180-4 — Secure Hash Standard
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

#include "sha256.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/* SHA-256 Constants — first 32 bits of cube roots of primes 2..311   */
/* (FIPS 180-4, Section 4.2.2)                                        */
/* ------------------------------------------------------------------ */

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* SHA-256 initial hash values — first 32 bits of sqrt of primes 2..19 */
static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

#define ROTR(x, n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x)      (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x)      (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sig0(x)      (ROTR(x,  7) ^ ROTR(x, 18) ^ ((x) >>  3))
#define sig1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/* Store uint32_t big-endian into 4 bytes */
static inline void store_be32(uint8_t *dst, uint32_t val) {
    dst[0] = (val >> 24) & 0xFF;
    dst[1] = (val >> 16) & 0xFF;
    dst[2] = (val >>  8) & 0xFF;
    dst[3] = (val      ) & 0xFF;
}

/* Load 4 bytes big-endian into uint32_t */
static inline uint32_t load_be32(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] <<  8) |
           ((uint32_t)src[3]      );
}

/* ------------------------------------------------------------------ */
/* SHA-256 Block Compression                                           */
/* ------------------------------------------------------------------ */

static void sha256_compress(uint32_t state[8],
                             const uint8_t block[SHA256_BLOCK_SIZE]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;

    /* Prepare message schedule W */
    for (int i = 0; i < 16; i++)
        W[i] = load_be32(&block[i * 4]);
    for (int i = 16; i < 64; i++)
        W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];

    /* Initialise working variables */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* 64 rounds */
    for (int i = 0; i < 64; i++) {
        T1 = h + SIG1(e) + CH(e,f,g) + K[i] + W[i];
        T2 = SIG0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    /* Add compressed chunk to current hash */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void SHA256_init(SHA256_ctx *ctx) {
    memcpy(ctx->state, H0, sizeof(H0));
    ctx->bit_count  = 0;
    ctx->buffer_len = 0;
    memset(ctx->buffer, 0, SHA256_BLOCK_SIZE);
}

void SHA256_update(SHA256_ctx *ctx, const uint8_t *data, size_t length) {
    ctx->bit_count += (uint64_t)length * 8;

    while (length > 0) {
        size_t space = SHA256_BLOCK_SIZE - ctx->buffer_len;
        size_t copy  = length < space ? length : space;

        memcpy(&ctx->buffer[ctx->buffer_len], data, copy);
        ctx->buffer_len += copy;
        data   += copy;
        length -= copy;

        /* Process full block */
        if (ctx->buffer_len == SHA256_BLOCK_SIZE) {
            sha256_compress(ctx->state, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void SHA256_final(SHA256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
    uint64_t bit_count = ctx->bit_count;

    /* Append 0x80 padding byte */
    uint8_t pad = 0x80;
    SHA256_update(ctx, &pad, 1);

    /* Pad with zeros until buffer has 56 bytes (room for 8-byte length) */
    uint8_t zero = 0x00;
    while (ctx->buffer_len != 56)
        SHA256_update(ctx, &zero, 1);

    /* Append original message length as 64-bit big-endian */
    uint8_t len_bytes[8];
    for (int i = 7; i >= 0; i--) {
        len_bytes[i] = bit_count & 0xFF;
        bit_count >>= 8;
    }
    SHA256_update(ctx, len_bytes, 8);

    /* Output digest in big-endian */
    for (int i = 0; i < 8; i++)
        store_be32(&digest[i * 4], ctx->state[i]);
}

void SHA256(const uint8_t *data, size_t length,
            uint8_t digest[SHA256_DIGEST_SIZE]) {
    SHA256_ctx ctx;
    SHA256_init(&ctx);
    SHA256_update(&ctx, data, length);
    SHA256_final(&ctx, digest);
}

int SHA256_compare(const uint8_t a[SHA256_DIGEST_SIZE],
                   const uint8_t b[SHA256_DIGEST_SIZE]) {
    /*
     * Constant-time comparison — evaluates all 32 bytes regardless
     * of where the first difference occurs. Prevents timing attacks
     * where an attacker could deduce the correct hash byte-by-byte
     * by measuring response time.
     */
    uint8_t diff = 0;
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
        diff |= a[i] ^ b[i];
    return diff;
}