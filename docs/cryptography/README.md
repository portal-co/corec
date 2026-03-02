# Cryptography

This document describes the cryptographic design of `corec`. All algorithms and design decisions are chosen to be **publicly auditable**: the scheme can be reviewed and verified by any party without access to secret material.

---

## Guiding Principle: Open Cryptography

The cryptographic layer relies exclusively on:

- **Standardised, peer-reviewed algorithms** — no proprietary or custom constructions.
- **Open-source implementations** — every crate used is published on crates.io under an open licence and auditable by the community.
- **Conservative, post-quantum primitives** — all new key material uses algorithms that are secure against both classical and quantum adversaries.

Security through obscurity is explicitly rejected. The full algorithm suite, key formats, and wire formats are documented here and in the source code.

---

## Algorithm Suite

### Key Encapsulation — X-Wing (`x-wing` crate)

X-Wing is a hybrid KEM combining:

| Component | Algorithm | Security basis |
|---|---|---|
| Classical | X25519 ECDH | Discrete logarithm / DH |
| Post-quantum | ML-KEM-768 (CRYSTALS-Kyber) | Module LWE |
| Combiner | HKDF-SHA-256 | Hash-based |

X-Wing provides IND-CCA2 security. A ciphertext is secure as long as **either** the classical or the post-quantum component remains unbroken. This makes the system safe today and safe after a quantum computer is available.

**Public auditability:** X-Wing is an IETF draft (`draft-connolly-cfrg-xwing-kem`). Public keys, ciphertexts, and shared secrets can be verified against the published test vectors.

### Signatures — SLH-DSA (`slh-dsa` crate, FIPS 205)

SLH-DSA (formerly SPHINCS+) is a stateless hash-based signature scheme:

- **Security assumption:** collision resistance of the underlying hash (SHA-256 / SHAKE-256). No number-theoretic assumption; secure against quantum adversaries.
- **FIPS 205** — standardised by NIST in 2024.
- Signatures are used to authenticate key publications, audit-log entries, and protocol messages.

**Public auditability:** Any party with a signer's public key can verify any signature offline. There is no trusted third party in the verification path.

---

## Key Lifecycle

```
Client                              Server
  │                                    │
  ├─ generate keypair (local, no_std)  │
  ├─ publish public key ──────────────►│ (stored, unauthenticated access OK)
  │                                    │
  ├─ encapsulate to recipient pubkey   │
  ├─ send ciphertext ─────────────────►│ (server cannot decrypt)
  │                                    │
  └─ recipient decapsulates locally    │
```

- Key generation happens entirely on the client (`no_std`, no OS entropy dependency beyond the platform CSPRNG).
- The server is a **ciphertext relay**: it stores and forwards encrypted blobs but never has access to plaintext.
- Key rotation is supported; old ciphertexts remain decryptable with the corresponding old private key until explicitly discarded by the user.

---

## Compression (`comptx` crate)

The `comptx` crate provides line-oriented compression used to pack plaintext **before** encryption:

- Alphanumeric chunks are base64-decoded (compact binary form).
- Non-alphanumeric chunks are stored verbatim.
- Each chunk is prefixed with its byte length (little-endian u64) and a mode byte.

Compression is applied **before** encryption so that ciphertext size reveals minimal information. Compressing after encryption would not reduce size and would reveal compression ratios.

---

## Threat Model

| Threat | Mitigation |
|---|---|
| Server compromise | Server holds only ciphertexts and public keys; no plaintext exposure |
| Quantum adversary | Post-quantum KEM (X-Wing) and signatures (SLH-DSA) |
| Algorithm break (classical) | Hybrid KEM; break of X25519 alone does not compromise security |
| Audit log tampering | Append-only log; each entry is individually signed |
| Key compromise | Forward secrecy via ephemeral encapsulation keys (planned) |

---

## Auditing the Implementation

The full source is available under MPL-2.0. To audit:

1. All cryptographic code lives under `crates/encryption/` and `packages/cncryption/`.
2. Dependency versions are pinned in `Cargo.lock`; run `cargo audit` to check for known vulnerabilities.
3. Test vectors from the X-Wing IETF draft and NIST FIPS 205 are used to validate correctness.

No network calls are made during cryptographic operations; auditors can run tests entirely offline.

---

## See Also

- [Compliance](../compliance/README.md) — how these primitives satisfy regulatory requirements without compromising privacy
- [`x-wing` IETF draft](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
