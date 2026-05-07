/*
 * bootloader.h — Secure Bootloader Chain of Trust
 *
 * Implements a secure boot sequence for embedded firmware images:
 *
 *   1. Load firmware image
 *   2. Verify SHA-256 integrity hash
 *   3. Verify ECDSA signature with embedded public key
 *   4. Verify passkey access control
 *   5. BOOT or HALT
 *
 * This chain of trust ensures:
 *   - Integrity:     firmware has not been corrupted (SHA-256)
 *   - Authenticity:  firmware was signed by the trusted party (ECDSA)
 *   - Access control: only authorised boot attempts proceed (passkey)
 *
 * Usage:
 *   BOOTLOADER_ctx ctx;
 *   BOOTLOADER_init(&ctx, public_key_x, public_key_y);
 *   int result = BOOTLOADER_run(&ctx, firmware, size, signature, passphrase);
 */

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/sha256.h"
#include "../crypto/ecdsa.h"
#include "passkey.h"

/* Boot result codes */
#define BOOT_OK                  0
#define BOOT_ERR_HASH            1   /* Integrity check failed */
#define BOOT_ERR_SIGNATURE       2   /* Signature verification failed */
#define BOOT_ERR_PASSKEY         3   /* Passkey verification failed */
#define BOOT_ERR_LOCKED          4   /* Too many failed attempts */

/* Bootloader context */
typedef struct {
    ECDSA_public_key public_key;     /* Trusted public key from protected flash */
    PASSKEY_ctx      passkey;        /* Passkey access control state */
    uint8_t          ref_hash[SHA256_DIGEST_SIZE]; /* Reference hash of firmware */
    int              hash_set;       /* Whether reference hash has been set */
} BOOTLOADER_ctx;

/*
 * BOOTLOADER_init — initialise bootloader with trusted public key
 * In production: public key is stored in OTP/protected flash
 */
void BOOTLOADER_init(BOOTLOADER_ctx *ctx,
                     const uint8_t pub_x[ECDSA_FIELD_SIZE],
                     const uint8_t pub_y[ECDSA_FIELD_SIZE]);

/*
 * BOOTLOADER_set_passkey — set the expected passkey hash
 * In production: called once at manufacturing time
 */
void BOOTLOADER_set_passkey(BOOTLOADER_ctx *ctx, const char *passphrase);

/*
 * BOOTLOADER_set_ref_hash — store reference hash of expected firmware
 * In production: written to protected flash at manufacturing time
 */
void BOOTLOADER_set_ref_hash(BOOTLOADER_ctx *ctx,
                              const uint8_t hash[SHA256_DIGEST_SIZE]);

/*
 * BOOTLOADER_run — execute full secure boot sequence
 *
 * Parameters:
 *   ctx        — bootloader context
 *   firmware   — pointer to firmware image in flash
 *   size       — firmware image size in bytes
 *   sig        — ECDSA signature appended to firmware image
 *   passphrase — access passphrase (may be NULL if not required)
 *
 * Returns:
 *   BOOT_OK            — all checks passed, safe to jump to firmware
 *   BOOT_ERR_HASH      — firmware corrupted or tampered
 *   BOOT_ERR_SIGNATURE — firmware not signed by trusted key
 *   BOOT_ERR_PASSKEY   — wrong passphrase
 *   BOOT_ERR_LOCKED    — too many failed boot attempts
 */
int BOOTLOADER_run(BOOTLOADER_ctx *ctx,
                   const uint8_t *firmware,
                   size_t size,
                   const ECDSA_signature *sig,
                   const char *passphrase);

/*
 * BOOTLOADER_result_str — human-readable result string for logging
 */
const char *BOOTLOADER_result_str(int result);

#endif /* BOOTLOADER_H */