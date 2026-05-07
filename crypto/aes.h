/*
 * aes.h — AES-128 Encryption/Decryption
 *
 * Implements AES-128 (128-bit key, 10 rounds) in ECB and CBC modes.
 * No dynamic memory allocation — suitable for resource-constrained
 * embedded targets (ARM Cortex-M class).
 *
 * Usage:
 *   AES_ctx ctx;
 *   AES_init(&ctx, key);
 *   AES_CBC_encrypt(&ctx, iv, buffer, length);
 */

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

/* AES block and key sizes in bytes */
#define AES_BLOCK_SIZE   16   /* 128 bits */
#define AES_KEY_SIZE     16   /* 128-bit key */
#define AES_NUM_ROUNDS   10

/* AES context — holds expanded round keys */
typedef struct {
    uint8_t round_keys[11][16];  /* 11 round keys × 16 bytes */
} AES_ctx;

/*
 * AES_init — expand the 128-bit key into round keys
 * Must be called before any encrypt/decrypt operation.
 */
void AES_init(AES_ctx *ctx, const uint8_t key[AES_KEY_SIZE]);

/*
 * AES_ECB_encrypt — encrypt a single 16-byte block in place (ECB mode)
 * WARNING: ECB mode is deterministic — identical plaintext blocks
 * produce identical ciphertext. Use CBC for real firmware encryption.
 */
void AES_ECB_encrypt(const AES_ctx *ctx, uint8_t block[AES_BLOCK_SIZE]);

/*
 * AES_ECB_decrypt — decrypt a single 16-byte block in place (ECB mode)
 */
void AES_ECB_decrypt(const AES_ctx *ctx, uint8_t block[AES_BLOCK_SIZE]);

/*
 * AES_CBC_encrypt — encrypt buffer in CBC mode
 * buffer length must be a multiple of AES_BLOCK_SIZE.
 * iv is modified in place (last ciphertext block) after call.
 */
void AES_CBC_encrypt(const AES_ctx *ctx,
                     uint8_t iv[AES_BLOCK_SIZE],
                     uint8_t *buffer,
                     size_t length);

/*
 * AES_CBC_decrypt — decrypt buffer in CBC mode
 * buffer length must be a multiple of AES_BLOCK_SIZE.
 * iv is modified in place after call.
 */
void AES_CBC_decrypt(const AES_ctx *ctx,
                     uint8_t iv[AES_BLOCK_SIZE],
                     uint8_t *buffer,
                     size_t length);

#endif /* AES_H */