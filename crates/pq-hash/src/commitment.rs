//! Keccak-256 for the commitment layer (Merkle trees, FRI, Fiat-Shamir).
//!
//! Keccak-256 is the EVM's native hash (precompile `0x20`). Using it for every
//! commitment the on-chain verifier touches means the verifier never pays for a
//! non-native hash, and never has to implement one.

use tiny_keccak::{Hasher as _, Keccak};

use crate::digest::Digest32;
use crate::traits::CommitmentHasher;

/// The commitment-layer hasher: Keccak-256.
#[derive(Clone, Copy, Debug, Default)]
pub struct Keccak256Commitment;

impl Keccak256Commitment {
    /// Keccak-256 of an arbitrary byte string.
    #[must_use]
    pub fn keccak256(bytes: &[u8]) -> Digest32 {
        let mut k = Keccak::v256();
        let mut out = [0u8; 32];
        k.update(bytes);
        k.finalize(&mut out);
        Digest32::new(out)
    }
}

impl CommitmentHasher for Keccak256Commitment {
    fn hash(&self, parts: &[&[u8]]) -> Digest32 {
        let mut k = Keccak::v256();
        for part in parts {
            k.update(part);
        }
        let mut out = [0u8; 32];
        k.finalize(&mut out);
        Digest32::new(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_keccak256_of_empty() {
        // The canonical Keccak-256 empty-string vector, which is *not* the SHA3
        // one — the padding byte differs (0x06 vs 0x01).
        let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        let got = Keccak256Commitment::keccak256(&[]);
        let hex = hex::encode(got.as_bytes());
        assert_eq!(hex, expected);
    }

    #[test]
    fn keccak_differs_from_sha3_on_same_input() {
        use crate::shielded::Sha3_256Shielded;
        use crate::traits::ShieldedHasher as _;
        let k = Keccak256Commitment.hash(&[b"abc"]);
        let s = Sha3_256Shielded.hash_to_digest(b"", &[b"abc"]);
        assert_ne!(k, s);
    }

    #[test]
    fn pair_hash_is_concatenation() {
        let l = Keccak256Commitment::keccak256(b"L");
        let r = Keccak256Commitment::keccak256(b"R");
        let pair = Keccak256Commitment.hash_pair(&l, &r);
        let manual = Keccak256Commitment::keccak256(
            &[l.as_bytes().as_slice(), r.as_bytes().as_slice()].concat(),
        );
        assert_eq!(pair, manual);
    }
}
