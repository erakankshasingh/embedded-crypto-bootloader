/*
 * main.c — Secure Bootloader Demo
 *
 * Demonstrates the full chain of trust:
 *   1. Passkey access control
 *   2. SHA-256 firmware integrity verification
 *   3. ECDSA signature verification
 *   4. Boot decision (BOOT or HALT)
 *
 * Simulates a firmware image in memory and runs three scenarios:
 *   - Scenario 1: Valid firmware, correct passkey  → BOOT
 *   - Scenario 2: Tampered firmware                → HALT (hash fail)
 *   - Scenario 3: Wrong passkey                    → HALT (passkey fail)
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "crypto/aes.h"
#include "crypto/sha256.h"
#include "crypto/ecdsa.h"
#include "bootloader/bootloader.h"

/* ------------------------------------------------------------------ */
/* Simulated firmware image (16 bytes — one AES block for demo)       */
/* ------------------------------------------------------------------ */

static const uint8_t FIRMWARE[] = {
    0xDE,0xAD,0xBE,0xEF,0x01,0x02,0x03,0x04,
    0xCA,0xFE,0xBA,0xBE,0x08,0x09,0x0A,0x0B
};
static const size_t FIRMWARE_SIZE = sizeof(FIRMWARE);

/* ------------------------------------------------------------------ */
/* Demo trusted public key (secp256k1 generator point G as placeholder)
 * In production: replace with real signing key pair                  */
/* ------------------------------------------------------------------ */

static const uint8_t PUB_X[32] = {
    0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,
    0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
    0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,
    0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98
};

static const uint8_t PUB_Y[32] = {
    0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,
    0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
    0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,
    0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8
};

/* ------------------------------------------------------------------ */
/* Helper — print a byte array as hex                                 */
/* ------------------------------------------------------------------ */

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("  %-20s ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* Demo: AES-128 encryption/decryption                                */
/* ------------------------------------------------------------------ */

static void demo_aes(void) {
    printf("\n========================================\n");
    printf("  AES-128 CBC Encryption Demo\n");
    printf("========================================\n");

    uint8_t key[16] = {
        0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,
        0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C
    };
    uint8_t iv[16]  = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    uint8_t iv_backup[16];
    memcpy(iv_backup, iv, 16);

    uint8_t block[16] = {
        0x6B,0xC1,0xBE,0xE2,0x2E,0x40,0x9F,0x96,
        0xE9,0x3D,0x7E,0x11,0x73,0x93,0x17,0x2A
    };

    AES_ctx ctx;
    AES_init(&ctx, key);

    print_hex("Plaintext:", block, 16);

    uint8_t iv_enc[16];
    memcpy(iv_enc, iv_backup, 16);
    AES_CBC_encrypt(&ctx, iv_enc, block, 16);
    print_hex("Ciphertext:", block, 16);

    uint8_t iv_dec[16];
    memcpy(iv_dec, iv_backup, 16);
    AES_CBC_decrypt(&ctx, iv_dec, block, 16);
    print_hex("Decrypted:", block, 16);
}

/* ------------------------------------------------------------------ */
/* Demo: SHA-256 hashing                                              */
/* ------------------------------------------------------------------ */

static void demo_sha256(void) {
    printf("\n========================================\n");
    printf("  SHA-256 Integrity Demo\n");
    printf("========================================\n");

    uint8_t digest[SHA256_DIGEST_SIZE];
    SHA256(FIRMWARE, FIRMWARE_SIZE, digest);
    print_hex("Firmware hash:", digest, SHA256_DIGEST_SIZE);

    /* Tampered firmware */
    uint8_t tampered[sizeof(FIRMWARE)];
    memcpy(tampered, FIRMWARE, sizeof(FIRMWARE));
    tampered[0] ^= 0xFF;  /* flip one byte */

    uint8_t tampered_digest[SHA256_DIGEST_SIZE];
    SHA256(tampered, sizeof(tampered), tampered_digest);
    print_hex("Tampered hash:", tampered_digest, SHA256_DIGEST_SIZE);

    int match = SHA256_compare(digest, tampered_digest);
    printf("  Hashes match: %s\n", match == 0 ? "YES" : "NO (tampered detected)");
}

/* ------------------------------------------------------------------ */
/* Demo: Secure bootloader scenarios                                  */
/* ------------------------------------------------------------------ */

static void demo_bootloader(void) {
    printf("\n========================================\n");
    printf("  Secure Bootloader Chain of Trust Demo\n");
    printf("========================================\n");

    /* Compute reference hash of firmware */
    uint8_t ref_hash[SHA256_DIGEST_SIZE];
    SHA256(FIRMWARE, FIRMWARE_SIZE, ref_hash);

    /*
     * Build a dummy signature (r, s) — all 0xAA bytes.
     * In production: computed by offline signing tool with private key.
     * Here ECDSA_verify will return ECDSA_ERR_INVALID which we use
     * to demonstrate the HALT path cleanly.
     *
     * To demonstrate a passing signature, replace with a real
     * pre-computed signature for the FIRMWARE bytes above.
     */
    ECDSA_signature sig;
    memset(sig.r.bytes, 0xAA, 32);
    memset(sig.s.bytes, 0xBB, 32);

    BOOTLOADER_ctx ctx;

    /* --- Scenario 1: Wrong passkey → HALT --- */
    printf("\n--- Scenario 1: Wrong passkey ---\n");
    BOOTLOADER_init(&ctx, PUB_X, PUB_Y);
    BOOTLOADER_set_passkey(&ctx, "correct_passphrase");
    BOOTLOADER_set_ref_hash(&ctx, ref_hash);
    int r1 = BOOTLOADER_run(&ctx, FIRMWARE, FIRMWARE_SIZE,
                             &sig, "wrong_passphrase");
    printf("Result: %s\n", BOOTLOADER_result_str(r1));

    /* --- Scenario 2: Tampered firmware → HALT --- */
    printf("\n--- Scenario 2: Tampered firmware ---\n");
    BOOTLOADER_init(&ctx, PUB_X, PUB_Y);
    BOOTLOADER_set_passkey(&ctx, "correct_passphrase");
    BOOTLOADER_set_ref_hash(&ctx, ref_hash);
    uint8_t tampered[sizeof(FIRMWARE)];
    memcpy(tampered, FIRMWARE, sizeof(FIRMWARE));
    tampered[0] ^= 0xFF;
    int r2 = BOOTLOADER_run(&ctx, tampered, sizeof(tampered),
                             &sig, "correct_passphrase");
    printf("Result: %s\n", BOOTLOADER_result_str(r2));

    /* --- Scenario 3: Valid hash, invalid signature → HALT --- */
    printf("\n--- Scenario 3: Invalid ECDSA signature ---\n");
    BOOTLOADER_init(&ctx, PUB_X, PUB_Y);
    BOOTLOADER_set_passkey(&ctx, "correct_passphrase");
    BOOTLOADER_set_ref_hash(&ctx, ref_hash);
    int r3 = BOOTLOADER_run(&ctx, FIRMWARE, FIRMWARE_SIZE,
                             &sig, "correct_passphrase");
    printf("Result: %s\n", BOOTLOADER_result_str(r3));
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("\n╔══════════════════════════════════════════╗\n");
    printf("║    Embedded Crypto & Secure Bootloader   ║\n");
    printf("║    secp256k1 · AES-128 · SHA-256 · ECDSA ║\n");
    printf("╚══════════════════════════════════════════╝\n");

    demo_aes();
    demo_sha256();
    demo_bootloader();

    printf("\nDone.\n");
    return 0;
}