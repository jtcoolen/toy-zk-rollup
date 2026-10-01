//! Shielded keys.
//!
//! Two key kinds live here, deliberately distinct types:
//!
//! - [`SpendPublicKey`] — what a note commits to. Possession of the matching
//!   secret authorizes a spend. This is the SPHINCS+ verifying key, published in
//!   the note preimage.
//! - [`IncomingViewingKey`] — lets a watcher recognize funds arriving without
//!   being able to move them.
//!
//! # Why the secret key is not a type here
//!
//! The spend *secret* is owned by `pq-sign` (`SpendAuth::SecretKey`) and by the
//! wallet. Duplicating it here would create two secret types that can drift. This
//! crate only ever sees the secret as a `&[u8; 32]` passed into
//! [`Note::nullifier`](crate::note::Note::nullifier), and never stores it.

use core::fmt;

use pq_hash::ShieldedHasher;

/// Domain tag for spend-key derivation.
///
/// Consensus-critical, like the note and nullifier tags. Its length is **even**
/// on purpose: the in-circuit Keccak gadget packs bytes into 16-bit limbs and
/// requires an even total, so an odd tag would make the `pk_d` preimage
/// unrepresentable. `b"pq-rollup/spend-pk/v1"` is 21 bytes and unusable;
/// `b"pq-rollup/spendpk/v1"` is 20.
pub const DOMAIN_PK: &[u8] = b"pq-rollup/spendpk/v1";

/// Derive the spend public key from its secret.
///
/// `pk_d = H_shielded(DOMAIN_PK || sk_d)`
///
/// This function exists so the circuit and the native code agree *by
/// construction*. The STARK recomputes `pk_d` from `sk_d` in-circuit, which is
/// what makes a spend sound: the note's owner is proven by SHA3-256 preimage
/// knowledge, not by an off-chain assertion. See D-018 in the decisions log.
#[must_use]
pub fn derive_spend_pk<H: ShieldedHasher>(hasher: &H, sk_d: &[u8; 32]) -> SpendPublicKey {
    SpendPublicKey::from_bytes(*hasher.hash_to_digest(DOMAIN_PK, &[sk_d]).as_bytes())
}

/// A spend public key: the verifying half of a PQ spend keypair.
///
/// Stored as raw bytes so the domain model stays independent of the signature
/// scheme. `pq-sign` is the only crate that knows these bytes are a SPHINCS+
/// verifying key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SpendPublicKey([u8; 32]);

impl SpendPublicKey {
    /// Wrap raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SpendPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Truncated for the same reason as the digests: full keys in logs are a
        // correlation risk and unreadable anyway.
        let hex = hex::encode(&self.0[..4]);
        write!(f, "SpendPk({hex}..)")
    }
}

/// An incoming viewing key: recognize deposits, cannot spend.
///
/// Derived as `ivk = H_shielded(DOMAIN_IVK || sk_d)`. Because it is a hash of
/// the secret and not the secret itself, publishing it leaks only the ability to
/// see, not to move.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct IncomingViewingKey([u8; 32]);

impl IncomingViewingKey {
    /// Wrap raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for IncomingViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = hex::encode(&self.0[..4]);
        write!(f, "Ivk({hex}..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spend_key_debug_is_truncated() {
        let k = SpendPublicKey::from_bytes([0xcd; 32]);
        let s = format!("{k:?}");
        assert_eq!(s, "SpendPk(cdcdcdcd..)");
        assert!(!s.contains(&"cd".repeat(32)));
    }

    #[test]
    fn ivk_debug_is_truncated() {
        let k = IncomingViewingKey::from_bytes([0xef; 32]);
        assert_eq!(format!("{k:?}"), "Ivk(efefefef..)");
    }

    #[test]
    fn key_types_are_not_interchangeable() {
        // Compile-time property, asserted by construction: these are distinct
        // types with no conversion between them.
        let pk = SpendPublicKey::from_bytes([1; 32]);
        let ivk = IncomingViewingKey::from_bytes([1; 32]);
        assert_ne!(format!("{pk:?}"), format!("{ivk:?}"));
    }
}
