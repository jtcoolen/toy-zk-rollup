//! The note: the atomic unit of shielded value.
//!
//! A note is the shielded analogue of a coin. It is *created* by a transfer's
//! output and *destroyed* by a transfer's input, and it never exists on-chain in
//! the clear — only its 32-byte commitment does.
//!
//! # Field roles
//!
//! | Field | Secret? | Role |
//! |---|---|---|
//! | `value`   | hidden  | The amount. Range-proven, never revealed. |
//! | `rho`     | secret  | Binds the note to a unique nullifier, so two notes never share one. |
//! | `psi`     | secret  | Randomness, so the commitment is hiding. |
//! | `pk_d`    | public-to-owner | The destination spend key. |
//!
//! `rho` is what makes nullifiers safe. Without it, `nullifier = H(sk)` would be
//! the same for every note a key owns, so spending one note would reveal that all
//! the key's other notes exist. A per-note `rho` makes each nullifier unique and
//! unlinkable.

use pq_hash::{CommitmentHasher, NoteHash, ShieldedHasher};

use crate::keys::SpendPublicKey;

/// Domain separation tag for note commitments. This is part of the
/// consensus-critical preimage format: changing it changes every commitment and
/// invalidates the chain.
///
/// `pub` rather than `pub(crate)` because the prover's in-circuit AIR must hash
/// the *exact* same preimage as [`Note::commit`] and [`Note::nullifier`]; a
/// duplicated literal in the prover could drift from this one silently. Sharing
/// the constant makes the two sides agree by construction, and a prover test
/// pins the circuit's output to these bytes.
///
/// The tag is deliberately an even number of bytes. Circuit limbs pack two bytes
/// each, so an odd-length preimage cannot be limb-aligned; a tag of 21 bytes
/// would make the spend-key derivation unbuildable.
pub const DOMAIN_NOTE: &[u8] = b"pq-rollup/note-commit/v1";

/// Domain separation tag for nullifiers; consensus-critical, as [`DOMAIN_NOTE`].
pub const DOMAIN_NULLIFIER: &[u8] = b"pq-rollup/nullifier/v1";

/// A shielded note.
///
/// `Copy` and small so it can be moved through witness-generation code without
/// allocation. Nothing here is `Debug` with real contents — see the module docs
/// on [`crate::keys`] for why.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Note {
    /// The hidden amount.
    pub(crate) value: u64,
    /// The nullifier seed. Unique per note.
    pub(crate) rho: [u8; 32],
    /// Commitment randomness.
    pub(crate) psi: [u8; 32],
    /// Who can spend this note.
    pub(crate) pk_d: SpendPublicKey,
}

impl Note {
    /// Build a note from its explicit components.
    ///
    /// Every argument here is secret material except `pk_d`. Callers generating
    /// `rho`/`psi` must use a CSPRNG; a predictable `rho` collides nullifiers and
    /// a predictable `psi` breaks hiding.
    #[must_use]
    pub const fn new(value: u64, rho: [u8; 32], psi: [u8; 32], pk_d: SpendPublicKey) -> Self {
        Self {
            value,
            rho,
            psi,
            pk_d,
        }
    }

    /// The hidden amount.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// The nullifier seed.
    #[must_use]
    pub const fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    /// The commitment randomness.
    #[must_use]
    pub const fn psi(&self) -> &[u8; 32] {
        &self.psi
    }

    /// The spend key that unlocks this note.
    #[must_use]
    pub const fn pk_d(&self) -> &SpendPublicKey {
        &self.pk_d
    }

    /// Commit the note to the tree.
    ///
    /// `cm = H_cm(DOMAIN || value || rho || psi || pk_d)`
    ///
    /// The commitment uses the [`CommitmentHasher`] (Keccak-256) because it is
    /// Merkleized and verified on-chain. The field order is fixed and must match
    /// the in-circuit AIR exactly.
    #[must_use]
    pub fn commit<H: CommitmentHasher>(&self, hasher: &H) -> NoteHash {
        let value = self.value.to_le_bytes();
        let pk_d = self.pk_d.as_bytes();
        NoteHash::from_digest(hasher.hash(&[DOMAIN_NOTE, &value, &self.rho, &self.psi, pk_d]))
    }

    /// The nullifier that destroys this note.
    ///
    /// `nf = H_shielded(DOMAIN || sk_d || rho)`
    ///
    /// This uses the [`ShieldedHasher`] (SHA3-256), *not* the commitment hasher:
    /// the nullifier is user-facing privacy material, not an on-chain Merkle
    /// leaf, so it gets the user-mandated FIPS-202 primitive.
    ///
    /// `rho` is mixed in so that the nullifier is unique per note rather than
    /// per key.
    #[must_use]
    pub fn nullifier<H: ShieldedHasher>(&self, hasher: &H, sk_d: &[u8; 32]) -> pq_hash::Nullifier {
        pq_hash::Nullifier::from_digest(hasher.hash_to_digest(DOMAIN_NULLIFIER, &[sk_d, &self.rho]))
    }
}

/// Redacted debug: shows that a note exists and its value, never its secrets.
///
/// `value` is shown because in tests it is the thing under discussion; the
/// blinding factors and the nullifier seed are never shown.
impl core::fmt::Debug for Note {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Note")
            .field("value", &self.value)
            .field("rho", &"[redacted]")
            .field("psi", &"[redacted]")
            .field("pk_d", &self.pk_d)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_hash::Poseidon2Commitment;

    fn note(value: u64, seed: u8) -> Note {
        Note::new(
            value,
            [seed; 32],
            [seed.wrapping_add(1); 32],
            SpendPublicKey::from_bytes([seed.wrapping_add(2); 32]),
        )
    }

    #[test]
    fn commitment_is_deterministic() {
        let h = Poseidon2Commitment::default();
        assert_eq!(note(10, 1).commit(&h), note(10, 1).commit(&h));
    }

    #[test]
    fn value_changes_the_commitment() {
        let h = Poseidon2Commitment::default();
        assert_ne!(note(10, 1).commit(&h), note(11, 1).commit(&h));
    }

    #[test]
    fn randomness_changes_the_commitment() {
        // Two notes with the same value and key but different psi must not collide,
        // otherwise the commitment is not hiding.
        let h = Poseidon2Commitment::default();
        let a = note(10, 1);
        let mut b = note(10, 1);
        b.psi = [9; 32];
        assert_ne!(a.commit(&h), b.commit(&h));
    }

    #[test]
    fn distinct_rho_gives_distinct_nullifiers_for_one_key() {
        // This is the whole reason rho exists.
        let h = pq_hash::Sha3_256Shielded;
        let sk = [7u8; 32];
        let a = note(10, 1).nullifier(&h, &sk);
        let b = note(10, 2).nullifier(&h, &sk);
        assert_ne!(a, b);
    }

    #[test]
    fn debug_never_leaks_secrets() {
        let n = note(10, 0xab);
        let rendered = format!("{n:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("abab"));
    }
}
