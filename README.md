# @portal-solutions/corec

An early-stage Rust workspace implementing post-quantum end-to-end-encrypted cryptographic primitives for the Portal Solutions platform. The codebase is currently two small `no_std` Rust crates plus a skeleton of planned JS packages; no API layer or network code exists yet.

---

## What it is

`corec` is intended to be the cryptographic core of a privacy-first messaging/communication API where the server acts as a ciphertext relay and never holds keys capable of decrypting user content. The design is post-quantum: all key material uses algorithms that are secure against both classical and quantum adversaries.

---

## Current state

Two Rust crates are implemented and tested. Everything else (JS packages, application layer, API, harness tooling) is a directory placeholder.

### `crates/encryption/keys`

Implements a deterministic key derivation hierarchy rooted in a 32-byte `UserSecretKey`:

- **KDF:** `SHAKE-256(domain || 0x00 || secret)[..96]` — domain-separated per algorithm and version, preventing key reuse across contexts.
- **Signing subkey:** Derives an `SLH-DSA-SHAKE-256s` (FIPS 205 / SPHINCS+) signing key under the domain tag `corec.sign.v1`. The corresponding verifying key is the user's main public identity key.
- **Subkey attestation:** Any other subkey's public bytes can be signed with `SigningSubkey::sign_public_key`, producing a `SignedPublicKey` (~29 800 bytes stack-allocated due to SLH-DSA signature size) that any third party can verify offline with only the user's public key.
- **Additional seeds:** `UserSecretKey::derive_seed(domain)` produces 96 bytes of seed material for other subkeys (e.g. X-Wing KEM keys).
- **Zeroization:** `UserSecretKey` and `SubkeySeed` are zeroized on drop via the `zeroize` crate. The inner `SigningKey` does not yet implement `Zeroize`.
- **`no_std`:** No heap allocator required.

Dependencies: `slh-dsa 0.2.0-rc.4`, `sha3 0.11.0-rc.7`, `zeroize 1.8.1`.

### `crates/encryption/comptx`

A line-oriented compression codec intended to reduce plaintext size before encryption (compressing before encrypting reduces ciphertext size; compressing after provides no benefit and would leak compression ratios).

- Lines are split on `\n`.
- Each chunk gets a 9-byte header: 8-byte little-endian `u64` length + 1-byte mode flag.
- **Mode 0 (alphanumeric):** the chunk is treated as base64 and decoded to binary — effectively the inverse of base64 encoding, storing binary data more compactly.
- **Mode 1 (other):** the chunk is stored verbatim.
- Provides `compress` (returns a `u8` iterator) and `decompress` (stateful iterator using an internal FSM).
- **`no_std`:** No allocator required.

Dependencies: `base64 0.22.1`, `either 1.15.0`.

---

## Planned / not yet implemented

The following are documented as future work but have no code:

- **X-Wing KEM integration** (`x-wing 0.1.0-pre.2` is listed as a workspace dependency but no crate uses it yet) — a hybrid KEM combining X25519 ECDH with ML-KEM-768 (CRYSTALS-Kyber).
- **JS packages** (`packages/app`, `packages/cncryption`, `packages/safety`, `packages/taps`) — all empty placeholder directories.
- **Application and API layer** (`crates/app`, `crates/safety`, `crates/taps`) — all empty placeholder directories.
- **Zero-knowledge proofs** — described in design docs, not started.
- **Witness encryption** — described in design docs as a longer-horizon research item.
- **Forward secrecy** via ephemeral encapsulation keys.
- **Cloudflare Workers** target (indicated by `@cloudflare/workers-types` dev dependency in `package.json`).

---

## Cryptographic design (summary)

Full details are in [`docs/cryptography/README.md`](docs/cryptography/README.md).

| Role | Algorithm | Crate | Status |
|---|---|---|---|
| Signatures / identity | SLH-DSA-SHAKE-256s (FIPS 205) | `slh-dsa` | Implemented |
| KEM / session keys | X-Wing (X25519 + ML-KEM-768) | `x-wing` | Dependency only, not wired |
| KDF | SHAKE-256 | `sha3` | Implemented |
| Pre-encryption compression | Custom line codec | `comptx` | Implemented |

The server threat model assumes the server is compromised or adversarial: it stores only ciphertexts and public keys and cannot decrypt user content.

Lawful-intercept and government backdoor mechanisms are explicitly out of scope.

---

## Repository layout

```
corec/
├── Cargo.toml                  # Rust workspace (members: comptx, keys)
├── package.json                # JS workspace root (no members yet)
├── crates/
│   └── encryption/
│       ├── comptx/             # Pre-encryption line compression codec (no_std)
│       └── keys/               # Key derivation + SLH-DSA signing (no_std)
├── packages/                   # JS package placeholders (all empty)
├── docs/
│   ├── cryptography/README.md  # Algorithm suite and key lifecycle design
│   └── compliance/README.md    # Privacy-first compliance posture
├── harness/                    # Test harness placeholder (empty)
├── tests/
│   └── example.test.js         # Vitest placeholder (1+1=2)
├── TESTING.md                  # Testing conventions
└── the-fog.md                  # Background context / motivation
```

---

## Running tests

**Rust:**
```sh
cargo test
```

**JS (placeholder only):**
```sh
npm install && npm test
```

---

## License

MPL-2.0
