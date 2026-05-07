/*
 * sha256.h — SHA-256 Hash Algorithm
 *
 * Implements SHA-256 producing a 256-bit (32-byte) digest.
 * No dynamic memory allocation — suitable for resource-constrained
 * embedded targets (ARM Cortex-M class).
 *
 * Usage:
 *   SHA256_ctx ctx;
 *   SHA256_init(&ctx);
 *   SHA256_update(&ctx, data, length);
 *   SHA256_final(&ctx, digest);
 *
 * Or single-call:
 *   SHA256(data, length, digest);
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_SIZE   32   /* 256 bits */
#define SHA256_BLOCK_SIZE    64   /* 512-bit block */

/* SHA-256 context */
typedef struct {
    uint32_t state[8];           /* Hash state (H0..H7) */
    uint64_t bit_count;          /* Total bits processed */
    uint8_t  buffer[SHA256_BLOCK_SIZE]; /* Partial block buffer */
    size_t   buffer_len;         /* Bytes currently in buffer */
} SHA256_ctx;

/*
 * SHA256_init — initialise context with standard IV (FIPS 180-4)
 */
void SHA256_init(SHA256_ctx *ctx);

/*
 * SHA256_update — feed data into the hash incrementally
 * Can be called multiple times before SHA256_final.
 */
void SHA256_update(SHA256_ctx *ctx, const uint8_t *data, size_t length);

/*
 * SHA256_final — finalise and output 32-byte digest
 * Context must not be used after this call.
 */
void SHA256_final(SHA256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

/*
 * SHA256 — single-call convenience function
 * Equivalent to init + update + final.
 */
void SHA256(const uint8_t *data, size_t length,
            uint8_t digest[SHA256_DIGEST_SIZE]);

/*
 * SHA256_compare — constant-time digest comparison
 * Returns 0 if equal, non-zero if different.
 * Constant-time prevents timing-based side channel attacks.
 */
int SHA256_compare(const uint8_t a[SHA256_DIGEST_SIZE],
                   const uint8_t b[SHA256_DIGEST_SIZE]);

#endif /* SHA256_H */