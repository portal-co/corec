# Compliance

This document describes the compliance posture of `corec` and the principles that govern how regulatory obligations are met **without compromising user privacy**.

---

## Guiding Principle: Privacy-First Compliance

Compliance requirements (audit trails, data retention, reporting) are satisfied through **cryptographic means** rather than by granting the platform access to plaintext user data. The system is designed so that:

- The server never holds keys capable of decrypting user content.
- Audit evidence is generated from verifiable commitments and signatures, not from plaintext inspection.
- Regulatory reports can be produced by the **user or their delegate** and verified by a third party without revealing underlying data to that third party.

---

## Data Minimisation

The API collects and retains only what is strictly necessary:

| Data type | Retention | Rationale |
|---|---|---|
| Public keys | Indefinite | Required for key lookup and forward secrecy |
| Ciphertext blobs | As agreed in service terms | Stored encrypted; server cannot read |
| Signatures / commitments | Indefinite | Audit trail without plaintext exposure |
| IP addresses / metadata | Session only | Dropped after connection closes |

No plaintext message content, no behavioural profiles, no third-party analytics.

---

## Audit Trails Without Plaintext

Compliance events (e.g. "message was sent", "key was rotated", "consent was recorded") are recorded as:

1. **Signed commitments** — each event is hashed and signed with `slh-dsa` (FIPS 205). The signature is verifiable by anyone with the public key.
2. **Append-only logs** — commitments are appended to an immutable log that can be inspected by auditors or regulators on request.
3. **Zero-knowledge proofs** (planned) — for sensitive properties (e.g. "this message was sent before date X") proofs will be constructed so the property can be verified without revealing the message.

---

## User Consent and Control

- Encryption keys are generated client-side. The server holds only public keys.
- Users can rotate or revoke their keys at any time; revocation is recorded in the audit log.
- Data export and deletion requests are handled without requiring the server to decrypt anything: encrypted blobs are deleted and the deletion event is logged.

---

## Regulatory Considerations

This design is intended to be compatible with regulations that require auditability (e.g. financial services rules) while respecting privacy regulations (e.g. GDPR, CCPA) that prohibit unnecessary access to personal data. Specific regulatory mappings should be assessed by qualified legal counsel for each deployment jurisdiction.

Lawful-intercept or government backdoor mechanisms are **outside the scope** of this project and are incompatible with its threat model.

---

## See Also

- [Cryptography](../cryptography/README.md) — the cryptographic primitives that underpin these guarantees
