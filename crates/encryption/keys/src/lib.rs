//! Base key system for `corec`.
//!
//! A [`UserSecretKey`] is a 32-byte secret from which all cryptographic
//! subkeys are derived via a domain-separated SHAKE-256 KDF.  The
//! **signing subkey** (SLH-DSA-SHAKE-256s by default) anchors the user's
//! identity: its [`VerifyingKey`] is the user's **main public key**, and
//! every other subkey's serialised public material is attested by a
//! signature from that signing subkey.
//!
//! # Stack usage warning
//!
//! `SLH-DSA-SHAKE-256s` signatures are large (~29 792 bytes each).  Values
//! of [`Signature`] and [`SignedPublicKey`] are stack-allocated; calling
//! code must ensure sufficient stack space is available.  On constrained
//! platforms consider increasing the stack size or boxing these values
//! manually once an allocator is available.
//!
//! # Key derivation
//!
//! ```text
//! SHAKE-256( domain_tag || 0x00 || user_secret ) → 96 bytes
//!                                                    │
//!                               ┌────────────────────┤
//!                               │                    │
//!                          sk_seed[0..32]       sk_prf[32..64]
//!                               │                    │
//!                               └──────── slh_keygen_internal ──── pk_seed[64..96]
//!                                                    │
//!                                         SigningKey<Shake256s>
//! ```
//!
//! All signing uses the deterministic variant of SLH-DSA (no per-signature
//! randomness injected), so the same [`UserSecretKey`] always produces the
//! same key bundle.

#![no_std]
#![deny(missing_docs)]

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use slh_dsa::{
    Shake256s, Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The user's main public key: the SLH-DSA-SHAKE-256s verifying key of the
/// signing subkey.  Distribute this to allow others to verify that a set of
/// subkeys all belong to the same user.
pub type UserPublicKey = VerifyingKey<Shake256s>;

// ── User secret ─────────────────────────────────────────────────────────────

/// The 32-byte user secret from which all subkeys are deterministically
/// derived.  Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserSecretKey([u8; 32]);

impl UserSecretKey {
    /// Wraps an existing 32-byte secret.
    ///
    /// The caller is responsible for sourcing the bytes from a CSPRNG or a
    /// secure key-agreement protocol.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derives the signing subkey using SLH-DSA-SHAKE-256s.
    ///
    /// The returned [`SigningSubkey::verifying_key`] is the user's main public
    /// key.  All other subkey public bytes must be attested via
    /// [`SigningSubkey::sign_public_key`] before distribution.
    pub fn signing_subkey(&self) -> SigningSubkey {
        // Domain tag for the signing subkey; changing this produces a
        // completely different key.
        let seed = kdf(&self.0, b"corec.sign.v1");
        // slh_keygen_internal expects three N-byte (32-byte for Shake256s)
        // slices: sk_seed, sk_prf, pk_seed.
        let inner = SigningKey::<Shake256s>::slh_keygen_internal(
            &seed[..32],
            &seed[32..64],
            &seed[64..96],
        );
        SigningSubkey { inner }
    }

    /// Derives 96 bytes of raw subkey seed material for the given `domain`
    /// tag.
    ///
    /// Use this to construct non-signing subkeys (e.g. X-Wing KEM keys).
    /// The `domain` tag must be unique per algorithm and version to prevent
    /// key reuse across different cryptographic contexts.
    pub fn derive_seed(&self, domain: &[u8]) -> SubkeySeed {
        SubkeySeed(kdf(&self.0, domain))
    }
}

// ── Subkey seed ──────────────────────────────────────────────────────────────

/// 96 bytes of raw seed material derived from a [`UserSecretKey`].
///
/// Split this according to the target algorithm's requirements.  For example,
/// an X-Wing subkey might use the first 32 bytes as its secret seed.
/// Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubkeySeed([u8; 96]);

impl SubkeySeed {
    /// Returns the raw seed bytes.
    pub fn as_bytes(&self) -> &[u8; 96] {
        &self.0
    }
}

// ── Signing subkey ───────────────────────────────────────────────────────────

/// The SLH-DSA-SHAKE-256s signing subkey derived from a [`UserSecretKey`].
///
/// Its verifying key is the user's main public key; use
/// [`SigningSubkey::verifying_key`] to obtain and publish it.
///
/// # Note on zeroisation
/// The inner [`SigningKey`] does not currently implement [`Zeroize`]; treat
/// instances of this type as sensitive and drop them promptly.
pub struct SigningSubkey {
    inner: SigningKey<Shake256s>,
}

impl SigningSubkey {
    /// Returns a reference to the user's main public key.
    pub fn verifying_key(&self) -> &UserPublicKey {
        self.inner.as_ref()
    }

    /// Signs `key_bytes` (typically another subkey's serialised public key)
    /// and returns a [`SignedPublicKey`] binding those bytes to this user's
    /// identity.
    ///
    /// Signing is deterministic: the same `key_bytes` always yield the same
    /// signature for a given [`UserSecretKey`].
    ///
    /// # Stack usage
    /// The returned [`SignedPublicKey`] contains a ~29 792-byte
    /// [`Signature<Shake256s>`] inline on the stack; see the [crate-level
    /// warning](crate).
    pub fn sign_public_key<'a>(&self, key_bytes: &'a [u8]) -> SignedPublicKey<'a> {
        // try_sign on SigningKey<P> cannot fail (no I/O, no state).
        let signature = self.inner.try_sign(key_bytes).expect("slh-dsa sign failed");
        SignedPublicKey { key_bytes, signature }
    }
}

// ── Signed public key ────────────────────────────────────────────────────────

/// A subkey's public key bytes together with the signing subkey's
/// SLH-DSA-SHAKE-256s signature over them.
///
/// The `key_bytes` field borrows the slice passed to
/// [`SigningSubkey::sign_public_key`]; no heap allocation is performed.
///
/// Proving that [`key_bytes`](SignedPublicKey::key_bytes) belongs to a
/// particular user requires only that user's [`UserPublicKey`] and a call to
/// [`SignedPublicKey::verify`].  No trusted third party is involved.
///
/// # Stack usage
/// `signature` is ~29 792 bytes; see the [crate-level warning](crate).
pub struct SignedPublicKey<'a> {
    /// The serialised public key bytes of the subkey.
    pub key_bytes: &'a [u8],
    /// The SLH-DSA-SHAKE-256s signature over [`key_bytes`](Self::key_bytes),
    /// produced by the user's [`SigningSubkey`].
    pub signature: Signature<Shake256s>,
}

impl<'a> SignedPublicKey<'a> {
    /// Verifies the signature against `user_public_key`.
    ///
    /// Returns `Ok(())` if and only if the signature is valid, confirming
    /// that `key_bytes` was attested by the holder of the corresponding
    /// signing subkey.
    pub fn verify(
        &self,
        user_public_key: &UserPublicKey,
    ) -> Result<(), slh_dsa::signature::Error> {
        user_public_key.verify(self.key_bytes, &self.signature)
    }
}

// ── Internal KDF ─────────────────────────────────────────────────────────────

/// Derives 96 bytes from `secret` under `domain` using SHAKE-256.
///
/// ```text
/// output = SHAKE-256( domain || 0x00 || secret )[..96]
/// ```
///
/// The 0x00 byte acts as a length terminator, preventing a domain tag that is
/// a prefix of another from producing overlapping output.
fn kdf(secret: &[u8; 32], domain: &[u8]) -> [u8; 96] {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(&[0x00]);
    hasher.update(secret.as_ref());
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 96];
    reader.read(&mut out);
    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> UserSecretKey {
        UserSecretKey::from_bytes([0x42u8; 32])
    }

    #[test]
    fn signing_subkey_is_deterministic() {
        let sk1 = secret().signing_subkey();
        let sk2 = secret().signing_subkey();
        assert_eq!(
            sk1.verifying_key().to_bytes().as_slice(),
            sk2.verifying_key().to_bytes().as_slice(),
        );
    }

    #[test]
    fn different_secrets_give_different_public_keys() {
        let sk_a = UserSecretKey::from_bytes([0xAAu8; 32]).signing_subkey();
        let sk_b = UserSecretKey::from_bytes([0xBBu8; 32]).signing_subkey();
        assert_ne!(
            sk_a.verifying_key().to_bytes().as_slice(),
            sk_b.verifying_key().to_bytes().as_slice(),
        );
    }

    #[test]
    fn signed_public_key_verifies() {
        let usk = secret();
        let signing = usk.signing_subkey();
        let user_pk = signing.verifying_key().clone();

        let subkey_bytes = b"fake-subkey-public-key-bytes";
        let spk = signing.sign_public_key(subkey_bytes);

        assert_eq!(spk.key_bytes, subkey_bytes as &[u8]);
        assert!(spk.verify(&user_pk).is_ok());
    }

    #[test]
    fn tampered_key_bytes_fail_verification() {
        let usk = secret();
        let signing = usk.signing_subkey();
        let user_pk = signing.verifying_key().clone();

        // Reuse the signature over "original-bytes" but present different key_bytes.
        let spk = signing.sign_public_key(b"original-bytes");
        let tampered = SignedPublicKey {
            key_bytes: b"tampered-bytes",
            signature: spk.signature,
        };
        assert!(tampered.verify(&user_pk).is_err());
    }

    #[test]
    fn wrong_user_public_key_fails_verification() {
        let usk = secret();
        let signing = usk.signing_subkey();

        let other_pk = UserSecretKey::from_bytes([0xFFu8; 32])
            .signing_subkey()
            .verifying_key()
            .clone();

        let spk = signing.sign_public_key(b"some-subkey");
        assert!(spk.verify(&other_pk).is_err());
    }

    #[test]
    fn derive_seed_domain_separation() {
        let usk = secret();
        let seed_a = usk.derive_seed(b"corec.xwing.v1");
        let seed_b = usk.derive_seed(b"corec.other.v1");
        assert_ne!(seed_a.as_bytes(), seed_b.as_bytes());
    }

    #[test]
    fn signing_subkey_seed_differs_from_custom_seed() {
        let usk = secret();
        let seed = usk.derive_seed(b"corec.other.v1");
        let signing_seed = usk.derive_seed(b"corec.sign.v1");
        assert_ne!(seed.as_bytes(), signing_seed.as_bytes());
    }
}
