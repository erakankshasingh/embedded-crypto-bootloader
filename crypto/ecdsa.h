/*
 * ecdsa.h — ECDSA Signature Verification
 *
 * Implements ECDSA signature verification on curve secp256k1.
 * Signature generation is intentionally excluded — in a secure
 * bootloader, signing happens offline on a trusted workstation.
 * The embedded target only ever verifies.
 *
 * No dynamic memory allocation — suitable for ARM Cortex-M targets.
 *
 * Usage:
 *   ECDSA_public_key pub;
 *   ECDSA_signature  sig;
 *   // load pub and sig from flash...
 *   int result = ECDSA_verify(&pub, hash, &sig);
 *   if (result == ECDSA_OK) { // boot } else { // halt }
 */

#ifndef ECDSA_H
#define ECDSA_H

#include <stdint.h>
#include "sha256.h"

/* Field element size in bytes (256-bit curve) */
#define ECDSA_FIELD_SIZE   32

/* Return codes */
#define ECDSA_OK           0
#define ECDSA_ERR_INVALID  1
#define ECDSA_ERR_INFINITY 2

/*
 * 256-bit big-integer — stored as 32 bytes big-endian
 * Used for curve coordinates, scalars, and signature components
 */
typedef struct {
    uint8_t bytes[ECDSA_FIELD_SIZE];
} BigInt256;

/*
 * Elliptic curve point in affine coordinates (x, y)
 * Point at infinity represented by is_infinity flag
 */
typedef struct {
    BigInt256 x;
    BigInt256 y;
    int is_infinity;
} ECPoint;

/*
 * ECDSA public key — a point on the curve
 * In secure boot: stored in protected flash at manufacturing time
 */
typedef ECPoint ECDSA_public_key;

/*
 * ECDSA signature — (r, s) pair
 * In secure boot: appended to firmware image by signing tool
 */
typedef struct {
    BigInt256 r;
    BigInt256 s;
} ECDSA_signature;

/*
 * ECDSA_verify — verify a signature against a message hash
 *
 * Parameters:
 *   pub    — public key (curve point)
 *   hash   — SHA-256 digest of the message (32 bytes)
 *   sig    — (r, s) signature pair
 *
 * Returns:
 *   ECDSA_OK          — signature valid, firmware is authentic
 *   ECDSA_ERR_INVALID — signature invalid, reject firmware
 *   ECDSA_ERR_INFINITY — point at infinity encountered, reject
 */
int ECDSA_verify(const ECDSA_public_key *pub,
                 const uint8_t hash[SHA256_DIGEST_SIZE],
                 const ECDSA_signature *sig);

/*
 * ECDSA_load_public_key — load public key from byte array
 * Expects 64 bytes: 32 bytes X coordinate + 32 bytes Y coordinate
 * big-endian, uncompressed point format (no 0x04 prefix).
 */
void ECDSA_load_public_key(ECDSA_public_key *pub,
                            const uint8_t x[ECDSA_FIELD_SIZE],
                            const uint8_t y[ECDSA_FIELD_SIZE]);

/*
 * ECDSA_load_signature — load signature from byte array
 * Expects 64 bytes: 32 bytes r + 32 bytes s, big-endian.
 */
void ECDSA_load_signature(ECDSA_signature *sig,
                           const uint8_t r[ECDSA_FIELD_SIZE],
                           const uint8_t s[ECDSA_FIELD_SIZE]);

#endif /* ECDSA_H */