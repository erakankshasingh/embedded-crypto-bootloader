/*
 * passkey.h — Passphrase/Passkey Access Control
 *
 * Implements passphrase-based access control for secure bootloader.
 * Uses SHA-256 hashing to store and verify passphrases without
 * storing the plaintext — suitable for resource-constrained targets.
 *
 * In a real system:
 *   - The passkey hash is stored in protected/OTP flash at manufacturing
 *   - The passkey itself is never stored on the device
 *   - Failed attempts trigger lockout to prevent brute force
 *
 * Usage:
 *   PASSKEY_store_hash(hash_storage, "mypassphrase");
 *   int result = PASSKEY_verify("mypassphrase", hash_storage);
 *   if (result == PASSKEY_OK) { // grant access }
 */

#ifndef PASSKEY_H
#define PASSKEY_H

#include <stdint.h>
#include <stddef.h>
#include "sha256.h"

/* Return codes */
#define PASSKEY_OK           0
#define PASSKEY_ERR_WRONG    1
#define PASSKEY_ERR_LOCKED   2

/* Maximum failed attempts before lockout */
#define PASSKEY_MAX_ATTEMPTS 3

/* Passkey context — tracks attempt counter */
typedef struct {
    uint8_t  stored_hash[SHA256_DIGEST_SIZE]; /* SHA-256 of correct passkey */
    int      attempts;                         /* Failed attempt counter */
    int      locked;                           /* Lockout flag */
} PASSKEY_ctx;

/*
 * PASSKEY_init — initialise context
 * Call before any other passkey operation.
 */
void PASSKEY_init(PASSKEY_ctx *ctx);

/*
 * PASSKEY_store_hash — hash and store a passphrase
 * In production: called once at manufacturing time.
 * passphrase: null-terminated string
 */
void PASSKEY_store_hash(PASSKEY_ctx *ctx, const char *passphrase);

/*
 * PASSKEY_verify — verify a passphrase attempt
 * Uses constant-time comparison to prevent timing attacks.
 * Increments attempt counter on failure.
 * Returns PASSKEY_ERR_LOCKED after PASSKEY_MAX_ATTEMPTS failures.
 */
int PASSKEY_verify(PASSKEY_ctx *ctx, const char *passphrase);

/*
 * PASSKEY_is_locked — check if context is locked out
 */
int PASSKEY_is_locked(const PASSKEY_ctx *ctx);

/*
 * PASSKEY_reset — reset attempt counter (requires privileged call)
 * In production: only accessible via secure debug interface.
 */
void PASSKEY_reset(PASSKEY_ctx *ctx);

#endif /* PASSKEY_H */