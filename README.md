# Embedded Crypto & Secure Bootloader

A C implementation of core cryptographic primitives and a secure bootloader
simulation for resource-constrained embedded systems (ARM Cortex-M class).

Demonstrates the foundational security mechanisms used in automotive and
industrial embedded controllers — implemented from scratch without external
crypto libraries.

---

## What This Project Demonstrates

- **AES-128** symmetric encryption/decryption (ECB and CBC modes)
- **SHA-256** hash-based integrity verification
- **ECDSA** asymmetric signature verification
- **Secure Bootloader** — chain of trust: hash verify → signature verify → boot decision
- **Passphrase/Passkey** access control on simulated constrained hardware

---

## Project Structure

embedded-crypto-bootloader/
├── crypto/
│   ├── aes.c / aes.h        # AES-128 ECB and CBC from scratch
│   ├── sha256.c / sha256.h  # SHA-256 hash algorithm
│   └── ecdsa.c / ecdsa.h    # ECDSA signature verification
├── bootloader/
│   ├── bootloader.c         # Secure boot chain of trust
│   └── passkey.c            # Passphrase-based access control
├── tests/
│   └── test_crypto.c        # Known-answer tests (KAT) for all algorithms
├── main.c                   # Demo: sign, verify, boot or reject
├── Makefile
└── README.md

---

## Build & Run

```bash
# Build everything
make

# Run the secure boot demo
./bootloader_demo

# Run crypto tests
./test_crypto
```

---

## Crypto Primitives

### AES-128
- Block cipher, 128-bit key, 10 rounds
- Modes: ECB (Electronic Codebook), CBC (Cipher Block Chaining)
- Used for: firmware image encryption, data-at-rest protection

### SHA-256
- Cryptographic hash function, 256-bit digest
- Used for: firmware integrity verification, hash chaining in bootloader

### ECDSA
- Elliptic Curve Digital Signature Algorithm
- Curve: secp256k1
- Used for: firmware image signing and verification in secure boot

---

## Secure Boot Chain of Trust

┌─────────────────────────────────────────────┐
│              SECURE BOOTLOADER              │
│                                             │
│  1. Load firmware image from flash          │
│  2. Compute SHA-256 hash of image           │
│  3. Compare against stored reference hash   │
│  4. Verify ECDSA signature with public key  │
│  5. Check passkey access control            │
│  6. BOOT (pass) or HALT (fail)              │
└─────────────────────────────────────────────┘

---

## Security Concepts Covered

| Concept                        | Implementation                    |
|-------------------------------|-----------------------------------|
| Symmetric encryption           | AES-128 ECB/CBC                   |
| Asymmetric signing/verification| ECDSA secp256k1                   |
| Integrity verification         | SHA-256 hash comparison           |
| Secure boot chain of trust     | Hash + signature + passkey        |
| Access control                 | Passphrase/Passkey verification   |
| Constant-time comparison       | Anti-timing-attack hash compare   |

---

## Target Platform

Designed for ARM Cortex-M class microcontrollers.
Builds and runs on any POSIX system (Linux/macOS) for simulation.

---

## Background

Cryptographic security in embedded systems requires balancing three competing
constraints: security strength, code size, and performance. This project
implements production-relevant algorithms in portable C, without heap
allocation or external dependencies, reflecting the constraints of real
embedded security controllers.

---

## Roadmap

- [x] AES-128 ECB/CBC
- [ ] SHA-256
- [ ] ECDSA signature verification
- [ ] Secure bootloader chain of trust
- [ ] Passkey access control
- [ ] Known-answer tests (KAT)

---

## Author

Built as a portfolio project demonstrating embedded security and cryptography
knowledge relevant to automotive and industrial security controllers.