# corec — Codebase Documentation

`@portal-solutions/corec` is the end-to-end-encrypted API for Portal solutions. It is a dual-language monorepo: cryptographic core logic is written in **Rust** (no-std where possible) and the application/transport layers are written in **TypeScript** targeting Cloudflare Workers.

---

## Repository Layout

```
corec/
├── Cargo.toml                  # Rust workspace root (resolver = "3")
├── package.json                # Node/npm workspace root
├── vitest.config.js            # Vitest test runner config
├── TESTING.md                  # Guide to writing and running tests
│
├── crates/                     # Rust crates (compiled library code)
│   ├── encryption/
│   │   └── comptx/             # Compression + transaction encoding (no_std)
│   │       └── src/lib.rs      #   compress() / decompress() over base64 chunks
│   ├── app/                    # Application-layer crate (placeholder)
│   ├── safety/                 # Safety/validation crate (placeholder)
│   └── taps/                   # Tap/event-stream crate (placeholder)
│
├── packages/                   # TypeScript packages (npm)
│   ├── app/                    # Application package (placeholder)
│   ├── cncryption/             # Client-side crypto bindings (placeholder)
│   ├── safety/                 # Safety/validation package (placeholder)
│   └── taps/                   # Tap/event-stream package (placeholder)
│
├── harness/                    # Runtime integration tooling
│   └── README.md               # Instructions for build/run scripts
│
├── tests/                      # Top-level JS/TS integration tests (Vitest)
│   └── example.test.js
│
└── docs/                       # ← You are here
    ├── compliance/             # Compliance guidance (privacy-preserving)
    └── cryptography/           # Cryptographic design (publicly auditable)
```

---

## Core Dependencies

| Crate / Package | Role |
|---|---|
| [`x-wing`](https://crates.io/crates/x-wing) | Post-quantum KEM (X-Wing hybrid: X25519 + ML-KEM-768) |
| [`slh-dsa`](https://crates.io/crates/slh-dsa) | Post-quantum signatures (FIPS 205 SLH-DSA / SPHINCS+) |
| [`base64`](https://crates.io/crates/base64) | Base64 encoding/decoding (no_std, no alloc) |
| [`either`](https://crates.io/crates/either) | Sum type utility (no_std) |

---

## Running the Project

```bash
# JavaScript / TypeScript tests
npm install
npm test

# Rust tests
cargo test
```

---

## Further Reading

- [Compliance](./compliance/README.md) — regulatory approach and privacy guarantees
- [Cryptography](./cryptography/README.md) — cryptographic design and public auditability
- [Testing Guide](../TESTING.md) — how to write and run tests
- [Harness Guide](../harness/README.md) — runtime integration tooling
