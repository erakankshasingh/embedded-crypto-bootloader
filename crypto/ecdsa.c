/*
 * ecdsa.c — ECDSA Signature Verification on secp256k1
 *
 * Implements ECDSA verify only — signing is an offline operation.
 * Uses the secp256k1 curve parameters (same as Bitcoin, widely
 * analysed and trusted).
 *
 * Arithmetic is performed over GF(p) where p is the secp256k1 prime.
 * All operations use constant-size 256-bit integers (no heap).
 *
 * References:
 *   SEC 2: Recommended Elliptic Curve Domain Parameters
 *   https://www.secg.org/sec2-v2.pdf
 *
 *   FIPS 186-4 — Digital Signature Standard
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
 */

#include "ecdsa.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/* secp256k1 curve parameters                                          */
/* ------------------------------------------------------------------ */

/*
 * Prime field modulus p:
 * p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
 */
static const uint8_t SECP256K1_P[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
};

/* Curve order n (number of points on the curve) */
static const uint8_t SECP256K1_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

/* Generator point G — x coordinate */
static const uint8_t SECP256K1_GX[32] = {
    0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,
    0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
    0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,
    0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98
};

/* Generator point G — y coordinate */
static const uint8_t SECP256K1_GY[32] = {
    0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,
    0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
    0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,
    0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8
};

/* ------------------------------------------------------------------ */
/* 256-bit big integer arithmetic (big-endian byte arrays)            */
/* ------------------------------------------------------------------ */

/* Compare two 256-bit numbers. Returns -1, 0, or 1 */
static int bigint_cmp(const uint8_t a[32], const uint8_t b[32]) {
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}

/* Check if 256-bit number is zero */
static int bigint_is_zero(const uint8_t a[32]) {
    for (int i = 0; i < 32; i++)
        if (a[i]) return 0;
    return 1;
}

/* a = a mod m (simple reduction — a must be < 2m) */
static void bigint_mod(uint8_t a[32], const uint8_t m[32]) {
    if (bigint_cmp(a, m) >= 0) {
        /* subtract m from a */
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int diff = (int)a[i] - (int)m[i] - borrow;
            a[i]   = (uint8_t)(diff & 0xFF);
            borrow = (diff < 0) ? 1 : 0;
        }
    }
}

/* result = (a + b) mod m */
static void bigint_addmod(uint8_t result[32],
                           const uint8_t a[32],
                           const uint8_t b[32],
                           const uint8_t m[32]) {
    int carry = 0;
    for (int i = 31; i >= 0; i--) {
        int sum   = (int)a[i] + (int)b[i] + carry;
        result[i] = (uint8_t)(sum & 0xFF);
        carry     = sum >> 8;
    }
    bigint_mod(result, m);
}

/* result = (a - b) mod m */
static void bigint_submod(uint8_t result[32],
                           const uint8_t a[32],
                           const uint8_t b[32],
                           const uint8_t m[32]) {
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int diff  = (int)a[i] - (int)b[i] - borrow;
        result[i] = (uint8_t)(diff & 0xFF);
        borrow    = (diff < 0) ? 1 : 0;
    }
    if (borrow)
        bigint_addmod(result, result, m, m);
}

/*
 * Modular multiplication: result = (a * b) mod m
 * Uses double-and-add method — constant iterations, not constant time
 * (sufficient for verify-only bootloader, not for signing)
 */
static void bigint_mulmod(uint8_t result[32],
                           const uint8_t a[32],
                           const uint8_t b[32],
                           const uint8_t m[32]) {
    uint8_t tmp[32];
    memcpy(tmp, a, 32);
    memset(result, 0, 32);

    for (int i = 31; i >= 0; i--) {
        for (int bit = 0; bit < 8; bit++) {
            if ((b[i] >> bit) & 1)
                bigint_addmod(result, result, tmp, m);
            bigint_addmod(tmp, tmp, tmp, m);  /* tmp = tmp * 2 mod m */
        }
    }
}

/*
 * Modular inverse: result = a^-1 mod m
 * Uses Fermat's little theorem: a^-1 = a^(m-2) mod m
 * Valid when m is prime (which secp256k1 p and n are)
 */
static void bigint_invmod(uint8_t result[32],
                           const uint8_t a[32],
                           const uint8_t m[32]) {
    /* Compute exponent = m - 2 */
    uint8_t exp[32];
    memcpy(exp, m, 32);
    int borrow = 2;
    for (int i = 31; i >= 0 && borrow; i--) {
        int diff = (int)exp[i] - borrow;
        exp[i]   = (uint8_t)(diff & 0xFF);
        borrow   = (diff < 0) ? 1 : 0;
    }

    /* Square-and-multiply: result = a^exp mod m */
    uint8_t base[32];
    memcpy(base, a, 32);
    memset(result, 0, 32);
    result[31] = 1;  /* result = 1 */

    for (int i = 31; i >= 0; i--) {
        for (int bit = 0; bit < 8; bit++) {
            if ((exp[i] >> bit) & 1)
                bigint_mulmod(result, result, base, m);
            bigint_mulmod(base, base, base, m);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Elliptic curve point arithmetic (secp256k1, affine coordinates)    */
/* ------------------------------------------------------------------ */

/* Point doubling: R = 2P */
static void ec_point_double(ECPoint *R, const ECPoint *P,
                             const uint8_t p[32]) {
    if (P->is_infinity) { *R = *P; return; }

    uint8_t lambda[32], tmp[32], num[32], den[32];

    /* lambda = (3 * Px^2) / (2 * Py) mod p */
    bigint_mulmod(num, P->x.bytes, P->x.bytes, p);  /* Px^2 */
    memset(tmp, 0, 32); tmp[31] = 3;
    bigint_mulmod(num, num, tmp, p);                  /* 3 * Px^2 */

    memset(tmp, 0, 32); tmp[31] = 2;
    bigint_mulmod(den, P->y.bytes, tmp, p);           /* 2 * Py */
    bigint_invmod(den, den, p);
    bigint_mulmod(lambda, num, den, p);

    /* Rx = lambda^2 - 2*Px mod p */
    bigint_mulmod(R->x.bytes, lambda, lambda, p);
    bigint_submod(R->x.bytes, R->x.bytes, P->x.bytes, p);
    bigint_submod(R->x.bytes, R->x.bytes, P->x.bytes, p);

    /* Ry = lambda*(Px - Rx) - Py mod p */
    bigint_submod(tmp, P->x.bytes, R->x.bytes, p);
    bigint_mulmod(R->y.bytes, lambda, tmp, p);
    bigint_submod(R->y.bytes, R->y.bytes, P->y.bytes, p);

    R->is_infinity = 0;
}

/* Point addition: R = P + Q */
static void ec_point_add(ECPoint *R,
                          const ECPoint *P,
                          const ECPoint *Q,
                          const uint8_t p[32]) {
    if (P->is_infinity) { *R = *Q; return; }
    if (Q->is_infinity) { *R = *P; return; }

    uint8_t lambda[32], tmp[32], dx[32], dy[32];

    bigint_submod(dx, Q->x.bytes, P->x.bytes, p);
    bigint_submod(dy, Q->y.bytes, P->y.bytes, p);

    /* Check for point doubling case (P == Q) */
    if (bigint_is_zero(dx)) {
        if (bigint_is_zero(dy)) {
            ec_point_double(R, P, p);
        } else {
            R->is_infinity = 1;
        }
        return;
    }

    /* lambda = dy / dx mod p */
    bigint_invmod(tmp, dx, p);
    bigint_mulmod(lambda, dy, tmp, p);

    /* Rx = lambda^2 - Px - Qx mod p */
    bigint_mulmod(R->x.bytes, lambda, lambda, p);
    bigint_submod(R->x.bytes, R->x.bytes, P->x.bytes, p);
    bigint_submod(R->x.bytes, R->x.bytes, Q->x.bytes, p);

    /* Ry = lambda*(Px - Rx) - Py mod p */
    bigint_submod(tmp, P->x.bytes, R->x.bytes, p);
    bigint_mulmod(R->y.bytes, lambda, tmp, p);
    bigint_submod(R->y.bytes, R->y.bytes, P->y.bytes, p);

    R->is_infinity = 0;
}

/* Scalar multiplication: R = k * P using double-and-add */
static void ec_scalar_mul(ECPoint *R,
                           const uint8_t k[32],
                           const ECPoint *P,
                           const uint8_t p[32]) {
    ECPoint tmp = *P;
    R->is_infinity = 1;  /* R = point at infinity (identity) */

    for (int i = 31; i >= 0; i--) {
        for (int bit = 0; bit < 8; bit++) {
            if ((k[i] >> bit) & 1)
                ec_point_add(R, R, &tmp, p);
            ec_point_double(&tmp, &tmp, p);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void ECDSA_load_public_key(ECDSA_public_key *pub,
                            const uint8_t x[ECDSA_FIELD_SIZE],
                            const uint8_t y[ECDSA_FIELD_SIZE]) {
    memcpy(pub->x.bytes, x, ECDSA_FIELD_SIZE);
    memcpy(pub->y.bytes, y, ECDSA_FIELD_SIZE);
    pub->is_infinity = 0;
}

void ECDSA_load_signature(ECDSA_signature *sig,
                           const uint8_t r[ECDSA_FIELD_SIZE],
                           const uint8_t s[ECDSA_FIELD_SIZE]) {
    memcpy(sig->r.bytes, r, ECDSA_FIELD_SIZE);
    memcpy(sig->s.bytes, s, ECDSA_FIELD_SIZE);
}

int ECDSA_verify(const ECDSA_public_key *pub,
                 const uint8_t hash[SHA256_DIGEST_SIZE],
                 const ECDSA_signature *sig) {
    /*
     * ECDSA verification algorithm (FIPS 186-4, Section 6.4.2):
     *
     * Given: public key Q, message hash e, signature (r, s)
     * 1. Verify r, s are in [1, n-1]
     * 2. Compute w = s^-1 mod n
     * 3. Compute u1 = e*w mod n
     * 4. Compute u2 = r*w mod n
     * 5. Compute point X = u1*G + u2*Q
     * 6. Signature valid if X.x mod n == r
     */

    /* Step 1 — validate r and s are in range [1, n-1] */
    if (bigint_is_zero(sig->r.bytes) || bigint_is_zero(sig->s.bytes))
        return ECDSA_ERR_INVALID;
    if (bigint_cmp(sig->r.bytes, SECP256K1_N) >= 0)
        return ECDSA_ERR_INVALID;
    if (bigint_cmp(sig->s.bytes, SECP256K1_N) >= 0)
        return ECDSA_ERR_INVALID;

    /* Step 2 — w = s^-1 mod n */
    uint8_t w[32];
    bigint_invmod(w, sig->s.bytes, SECP256K1_N);

    /* Step 3 — u1 = hash * w mod n */
    uint8_t u1[32];
    bigint_mulmod(u1, hash, w, SECP256K1_N);

    /* Step 4 — u2 = r * w mod n */
    uint8_t u2[32];
    bigint_mulmod(u2, sig->r.bytes, w, SECP256K1_N);

    /* Step 5 — X = u1*G + u2*Q */
    ECPoint G;
    memcpy(G.x.bytes, SECP256K1_GX, 32);
    memcpy(G.y.bytes, SECP256K1_GY, 32);
    G.is_infinity = 0;

    ECPoint X1, X2, X;
    ec_scalar_mul(&X1, u1, &G,   SECP256K1_P);
    ec_scalar_mul(&X2, u2, pub,  SECP256K1_P);
    ec_point_add(&X, &X1, &X2,  SECP256K1_P);

    if (X.is_infinity)
        return ECDSA_ERR_INFINITY;

    /* Step 6 — verify X.x mod n == r */
    uint8_t xmod[32];
    memcpy(xmod, X.x.bytes, 32);
    bigint_mod(xmod, SECP256K1_N);

    return (bigint_cmp(xmod, sig->r.bytes) == 0) ? ECDSA_OK : ECDSA_ERR_INVALID;
}