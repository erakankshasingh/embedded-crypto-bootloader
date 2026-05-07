/*
 * passkey.c — Passphrase/Passkey Access Control Implementation
 *
 * SHA-256 based passphrase verification with lockout protection.
 * No heap allocation. No plaintext storage.
 */

#include "passkey.h"
#include <string.h>

void PASSKEY_init(PASSKEY_ctx *ctx) {
    memset(ctx->stored_hash, 0, SHA256_DIGEST_SIZE);
    ctx->attempts = 0;
    ctx->locked   = 0;
}

void PASSKEY_store_hash(PASSKEY_ctx *ctx, const char *passphrase) {
    /*
     * Hash the passphrase and store the digest.
     * The plaintext passphrase never persists in memory longer
     * than this function call.
     */
    SHA256((const uint8_t *)passphrase,
           strlen(passphrase),
           ctx->stored_hash);
}

int PASSKEY_verify(PASSKEY_ctx *ctx, const char *passphrase) {
    /* Check lockout first */
    if (ctx->locked)
        return PASSKEY_ERR_LOCKED;

    /* Hash the input passphrase */
    uint8_t input_hash[SHA256_DIGEST_SIZE];
    SHA256((const uint8_t *)passphrase,
           strlen(passphrase),
           input_hash);

    /* Constant-time comparison — prevents timing attacks */
    int result = SHA256_compare(input_hash, ctx->stored_hash);

    if (result != 0) {
        ctx->attempts++;
        if (ctx->attempts >= PASSKEY_MAX_ATTEMPTS) {
            ctx->locked = 1;
            return PASSKEY_ERR_LOCKED;
        }
        return PASSKEY_ERR_WRONG;
    }

    /* Success — reset attempt counter */
    ctx->attempts = 0;
    return PASSKEY_OK;
}

int PASSKEY_is_locked(const PASSKEY_ctx *ctx) {
    return ctx->locked;
}

void PASSKEY_reset(PASSKEY_ctx *ctx) {
    ctx->attempts = 0;
    ctx->locked   = 0;
}