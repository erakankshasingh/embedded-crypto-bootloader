/*
 * bootloader.c — Secure Bootloader Implementation
 *
 * Chain of trust: SHA-256 integrity → ECDSA authenticity → Passkey access
 */

#include "bootloader.h"
#include <string.h>
#include <stdio.h>

void BOOTLOADER_init(BOOTLOADER_ctx *ctx,
                     const uint8_t pub_x[ECDSA_FIELD_SIZE],
                     const uint8_t pub_y[ECDSA_FIELD_SIZE]) {
    ECDSA_load_public_key(&ctx->public_key, pub_x, pub_y);
    PASSKEY_init(&ctx->passkey);
    memset(ctx->ref_hash, 0, SHA256_DIGEST_SIZE);
    ctx->hash_set = 0;
}

void BOOTLOADER_set_passkey(BOOTLOADER_ctx *ctx, const char *passphrase) {
    PASSKEY_store_hash(&ctx->passkey, passphrase);
}

void BOOTLOADER_set_ref_hash(BOOTLOADER_ctx *ctx,
                              const uint8_t hash[SHA256_DIGEST_SIZE]) {
    memcpy(ctx->ref_hash, hash, SHA256_DIGEST_SIZE);
    ctx->hash_set = 1;
}

int BOOTLOADER_run(BOOTLOADER_ctx *ctx,
                   const uint8_t *firmware,
                   size_t size,
                   const ECDSA_signature *sig,
                   const char *passphrase) {

    printf("[BOOTLOADER] Starting secure boot sequence...\n");

    /* ------------------------------------------------------------ */
    /* Step 1 — Passkey access control                              */
    /* ------------------------------------------------------------ */
    printf("[BOOTLOADER] Step 1: Verifying passkey...\n");

    if (PASSKEY_is_locked(&ctx->passkey)) {
        printf("[BOOTLOADER] HALT — device is locked after too many failed attempts\n");
        return BOOT_ERR_LOCKED;
    }

    if (passphrase != NULL) {
        int pk_result = PASSKEY_verify(&ctx->passkey, passphrase);
        if (pk_result == PASSKEY_ERR_LOCKED) {
            printf("[BOOTLOADER] HALT — locked after failed passkey attempt\n");
            return BOOT_ERR_LOCKED;
        }
        if (pk_result != PASSKEY_OK) {
            printf("[BOOTLOADER] HALT — wrong passkey\n");
            return BOOT_ERR_PASSKEY;
        }
        printf("[BOOTLOADER] Passkey OK\n");
    }

    /* ------------------------------------------------------------ */
    /* Step 2 — SHA-256 integrity check                             */
    /* ------------------------------------------------------------ */
    printf("[BOOTLOADER] Step 2: Verifying firmware integrity (SHA-256)...\n");

    uint8_t computed_hash[SHA256_DIGEST_SIZE];
    SHA256(firmware, size, computed_hash);

    if (ctx->hash_set) {
        if (SHA256_compare(computed_hash, ctx->ref_hash) != 0) {
            printf("[BOOTLOADER] HALT — firmware hash mismatch\n");
            return BOOT_ERR_HASH;
        }
    }
    printf("[BOOTLOADER] Integrity OK\n");

    /* ------------------------------------------------------------ */
    /* Step 3 — ECDSA signature verification                        */
    /* ------------------------------------------------------------ */
    printf("[BOOTLOADER] Step 3: Verifying ECDSA signature...\n");

    int sig_result = ECDSA_verify(&ctx->public_key, computed_hash, sig);
    if (sig_result != ECDSA_OK) {
        printf("[BOOTLOADER] HALT — signature verification failed (code %d)\n",
               sig_result);
        return BOOT_ERR_SIGNATURE;
    }
    printf("[BOOTLOADER] Signature OK\n");

    /* ------------------------------------------------------------ */
    /* All checks passed — safe to boot                             */
    /* ------------------------------------------------------------ */
    printf("[BOOTLOADER] All checks passed — BOOTING firmware\n");
    return BOOT_OK;
}

const char *BOOTLOADER_result_str(int result) {
    switch (result) {
        case BOOT_OK:            return "BOOT OK";
        case BOOT_ERR_HASH:      return "INTEGRITY CHECK FAILED";
        case BOOT_ERR_SIGNATURE: return "SIGNATURE INVALID";
        case BOOT_ERR_PASSKEY:   return "WRONG PASSKEY";
        case BOOT_ERR_LOCKED:    return "DEVICE LOCKED";
        default:                 return "UNKNOWN ERROR";
    }
}