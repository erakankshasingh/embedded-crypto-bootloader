/*
 * test_crypto.c — Known-Answer Tests (KAT) for crypto primitives
 *
 * Uses official NIST test vectors to verify correctness of:
 *   - AES-128 ECB and CBC
 *   - SHA-256
 *   - SHA256_compare constant-time function
 *   - Passkey access control
 *   - Bootloader chain of trust
 *
 * Test vectors sourced from:
 *   NIST FIPS 197 (AES): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 *   NIST FIPS 180-4 (SHA-256): https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../crypto/aes.h"
#include "../crypto/sha256.h"
#include "../crypto/ecdsa.h"
#include "../bootloader/passkey.h"
#include "../bootloader/bootloader.h"

/* ------------------------------------------------------------------ */
/* Test framework                                                      */
/* ------------------------------------------------------------------ */

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name, condition)                                        \
    do {                                                             \
        tests_run++;                                                 \
        if (condition) {                                             \
            printf("  [PASS] %s\n", name);                          \
            tests_passed++;                                          \
        } else {                                                     \
            printf("  [FAIL] %s\n", name);                          \
            tests_failed++;                                          \
        }                                                            \
    } while (0)

/* Compare two byte arrays of given length */
static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    return memcmp(a, b, len) == 0;
}

/* ------------------------------------------------------------------ */
/* AES-128 ECB Tests — NIST FIPS 197 Appendix B                       */
/* ------------------------------------------------------------------ */

static void test_aes_ecb(void) {
    printf("\n--- AES-128 ECB (NIST FIPS 197 Appendix B) ---\n");

    /* NIST test vector */
    uint8_t key[16] = {
        0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,
        0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C
    };
    uint8_t plaintext[16] = {
        0x32,0x43,0xF6,0xA8,0x88,0x5A,0x30,0x8D,
        0x31,0x31,0x98,0xA2,0xE0,0x37,0x07,0x34
    };
    uint8_t expected_ciphertext[16] = {
        0x39,0x25,0x84,0x1D,0x02,0xDC,0x09,0xFB,
        0xDC,0x11,0x85,0x97,0x19,0x6A,0x0B,0x32
    };

    AES_ctx ctx;
    AES_init(&ctx, key);

    uint8_t block[16];

    /* Encrypt */
    memcpy(block, plaintext, 16);
    AES_ECB_encrypt(&ctx, block);
    TEST("AES-128 ECB encrypt (NIST vector)",
         bytes_eq(block, expected_ciphertext, 16));

    /* Decrypt back */
    AES_ECB_decrypt(&ctx, block);
    TEST("AES-128 ECB decrypt (round-trip)",
         bytes_eq(block, plaintext, 16));
}

/* ------------------------------------------------------------------ */
/* AES-128 CBC Tests — NIST SP 800-38A                                */
/* ------------------------------------------------------------------ */

static void test_aes_cbc(void) {
    printf("\n--- AES-128 CBC (NIST SP 800-38A) ---\n");

    uint8_t key[16] = {
        0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,
        0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C
    };
    uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    uint8_t plaintext[16] = {
        0x6B,0xC1,0xBE,0xE2,0x2E,0x40,0x9F,0x96,
        0xE9,0x3D,0x7E,0x11,0x73,0x93,0x17,0x2A
    };
    uint8_t expected[16] = {
        0x76,0x49,0xAB,0xAC,0x81,0x19,0xB2,0x46,
        0xCE,0xE9,0x8E,0x9B,0x12,0xE9,0x19,0x7D
    };

    AES_ctx ctx;
    AES_init(&ctx, key);

    uint8_t block[16];
    uint8_t iv_copy[16];

    /* Encrypt */
    memcpy(block, plaintext, 16);
    memcpy(iv_copy, iv, 16);
    AES_CBC_encrypt(&ctx, iv_copy, block, 16);
    TEST("AES-128 CBC encrypt (NIST vector)",
         bytes_eq(block, expected, 16));

    /* Decrypt */
    memcpy(iv_copy, iv, 16);
    AES_CBC_decrypt(&ctx, iv_copy, block, 16);
    TEST("AES-128 CBC decrypt (round-trip)",
         bytes_eq(block, plaintext, 16));

    /* Different keys produce different ciphertext */
    uint8_t key2[16] = {0};
    AES_ctx ctx2;
    AES_init(&ctx2, key2);
    uint8_t block2[16];
    uint8_t iv2[16] = {0};
    memcpy(block2, plaintext, 16);
    AES_CBC_encrypt(&ctx2, iv2, block2, 16);
    TEST("AES-128 CBC different keys → different ciphertext",
         !bytes_eq(block2, expected, 16));
}

/* ------------------------------------------------------------------ */
/* SHA-256 Tests — NIST FIPS 180-4                                    */
/* ------------------------------------------------------------------ */

static void test_sha256(void) {
    printf("\n--- SHA-256 (NIST FIPS 180-4) ---\n");

    uint8_t digest[SHA256_DIGEST_SIZE];

    /* NIST vector 1: "abc" */
    uint8_t expected1[32] = {
        0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,
        0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,
        0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,
        0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD
    };
    SHA256((const uint8_t *)"abc", 3, digest);
    TEST("SHA-256 of \"abc\" (NIST vector)",
         bytes_eq(digest, expected1, 32));

    /* NIST vector 2: empty string */
    uint8_t expected2[32] = {
        0xE3,0xB0,0xC4,0x42,0x98,0xFC,0x1C,0x14,
        0x9A,0xFB,0xF4,0xC8,0x99,0x6F,0xB9,0x24,
        0x27,0xAE,0x41,0xE4,0x64,0x9B,0x93,0x4C,
        0xA4,0x95,0x99,0x1B,0x78,0x52,0xB8,0x55
    };
    SHA256((const uint8_t *)"", 0, digest);
    TEST("SHA-256 of empty string (NIST vector)",
         bytes_eq(digest, expected2, 32));

    /* NIST vector 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
    const char *msg3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t expected3[32] = {
        0x24,0x8D,0x6A,0x61,0xD2,0x06,0x38,0xB8,
        0xE5,0xC0,0x26,0x93,0x0C,0x3E,0x60,0x39,
        0xA3,0x3C,0xE4,0x59,0x64,0xFF,0x21,0x67,
        0xF6,0xEC,0xED,0xD4,0x19,0xDB,0x06,0xC1
    };
    SHA256((const uint8_t *)msg3, strlen(msg3), digest);
    TEST("SHA-256 of long NIST vector",
         bytes_eq(digest, expected3, 32));

    /* Avalanche effect — 1 bit flip changes digest completely */
    uint8_t d1[32], d2[32];
    SHA256((const uint8_t *)"hello", 5, d1);
    SHA256((const uint8_t *)"iello", 5, d2);
    TEST("SHA-256 avalanche effect",
         !bytes_eq(d1, d2, 32));

    /* Constant-time compare — equal */
    TEST("SHA256_compare equal digests returns 0",
         SHA256_compare(d1, d1) == 0);

    /* Constant-time compare — not equal */
    TEST("SHA256_compare different digests returns non-zero",
         SHA256_compare(d1, d2) != 0);
}

/* ------------------------------------------------------------------ */
/* Passkey Tests                                                       */
/* ------------------------------------------------------------------ */

static void test_passkey(void) {
    printf("\n--- Passkey Access Control ---\n");

    PASSKEY_ctx ctx;
    PASSKEY_init(&ctx);
    PASSKEY_store_hash(&ctx, "secure_boot_2026");

    /* Correct passphrase */
    TEST("Correct passphrase accepted",
         PASSKEY_verify(&ctx, "secure_boot_2026") == PASSKEY_OK);

    /* Wrong passphrase */
    TEST("Wrong passphrase rejected",
         PASSKEY_verify(&ctx, "wrong_pass") == PASSKEY_ERR_WRONG);

    /* Lockout after max attempts */
    PASSKEY_init(&ctx);
    PASSKEY_store_hash(&ctx, "correct");
    PASSKEY_verify(&ctx, "wrong1");
    PASSKEY_verify(&ctx, "wrong2");
    int result = PASSKEY_verify(&ctx, "wrong3");
    TEST("Locked after max failed attempts",
         result == PASSKEY_ERR_LOCKED);

    /* Locked stays locked */
    TEST("Correct passphrase rejected when locked",
         PASSKEY_verify(&ctx, "correct") == PASSKEY_ERR_LOCKED);

    /* Reset clears lockout */
    PASSKEY_reset(&ctx);
    TEST("Passkey accepted after reset",
         PASSKEY_verify(&ctx, "correct") == PASSKEY_OK);
}

/* ------------------------------------------------------------------ */
/* Bootloader Chain of Trust Tests                                    */
/* ------------------------------------------------------------------ */

static void test_bootloader(void) {
    printf("\n--- Bootloader Chain of Trust ---\n");

    static const uint8_t firmware[] = {
        0xDE,0xAD,0xBE,0xEF,0x01,0x02,0x03,0x04
    };

    uint8_t pub_x[32] = {
        0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,
        0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
        0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,
        0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98
    };
    uint8_t pub_y[32] = {
        0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,
        0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
        0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,
        0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8
    };

    uint8_t ref_hash[SHA256_DIGEST_SIZE];
    SHA256(firmware, sizeof(firmware), ref_hash);

    ECDSA_signature sig;
    memset(sig.r.bytes, 0xAA, 32);
    memset(sig.s.bytes, 0xBB, 32);

    BOOTLOADER_ctx ctx;

    /* Wrong passkey → HALT */
    BOOTLOADER_init(&ctx, pub_x, pub_y);
    BOOTLOADER_set_passkey(&ctx, "correct");
    BOOTLOADER_set_ref_hash(&ctx, ref_hash);
    TEST("Wrong passkey halts boot",
         BOOTLOADER_run(&ctx, firmware, sizeof(firmware),
                        &sig, "wrong") == BOOT_ERR_PASSKEY);

    /* Tampered firmware → HALT */
    BOOTLOADER_init(&ctx, pub_x, pub_y);
    BOOTLOADER_set_passkey(&ctx, "correct");
    BOOTLOADER_set_ref_hash(&ctx, ref_hash);
    uint8_t tampered[sizeof(firmware)];
    memcpy(tampered, firmware, sizeof(firmware));
    tampered[0] ^= 0xFF;
    TEST("Tampered firmware halts boot",
         BOOTLOADER_run(&ctx, tampered, sizeof(tampered),
                        &sig, "correct") == BOOT_ERR_HASH);

    /* Invalid signature → HALT */
    BOOTLOADER_init(&ctx, pub_x, pub_y);
    BOOTLOADER_set_passkey(&ctx, "correct");
    BOOTLOADER_set_ref_hash(&ctx, ref_hash);
    TEST("Invalid signature halts boot",
         BOOTLOADER_run(&ctx, firmware, sizeof(firmware),
                        &sig, "correct") == BOOT_ERR_SIGNATURE);

    /* Lockout after repeated wrong passkeys */
    BOOTLOADER_init(&ctx, pub_x, pub_y);
    BOOTLOADER_set_passkey(&ctx, "correct");
    BOOTLOADER_set_ref_hash(&ctx, ref_hash);
    BOOTLOADER_run(&ctx, firmware, sizeof(firmware), &sig, "w1");
    BOOTLOADER_run(&ctx, firmware, sizeof(firmware), &sig, "w2");
    BOOTLOADER_run(&ctx, firmware, sizeof(firmware), &sig, "w3");
    TEST("Device locked after repeated failed boots",
         BOOTLOADER_run(&ctx, firmware, sizeof(firmware),
                        &sig, "correct") == BOOT_ERR_LOCKED);
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║   Embedded Crypto — Known-Answer Tests  ║\n");
    printf("╚══════════════════════════════════════════╝\n");

    test_aes_ecb();
    test_aes_cbc();
    test_sha256();
    test_passkey();
    test_bootloader();

    printf("\n========================================\n");
    printf("  Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed == 0)
        printf(" — ALL TESTS PASSED ✓\n");
    else
        printf(" — %d FAILED ✗\n", tests_failed);
    printf("========================================\n");

    return tests_failed == 0 ? 0 : 1;
}