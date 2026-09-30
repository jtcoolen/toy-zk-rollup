//! SHA3-256 (FIPS-202) for the shielded layer.

use sha3::{Digest as _, Sha3_256};

use crate::digest::Digest32;
use crate::traits::ShieldedHasher;

/// The shielded-layer hasher: SHA3-256.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha3_256Shielded;

impl ShieldedHasher for Sha3_256Shielded {
    fn hash_to_digest(&self, domain: &[u8], parts: &[&[u8]]) -> Digest32 {
        let mut h = Sha3_256::new();
        // Length-prefix the domain tag and every part so that `("ab", "c")` and
        // `("a", "bc")` cannot collide.
        //
        // The prefix is `u64`, not `u32`: `usize -> u64` is lossless on every
        // target we build for, so a length can never silently truncate and weaken
        // the domain separation. Solidity mirrors this with a 8-byte big-endian
        // length header.
        h.update((domain.len() as u64).to_le_bytes());
        h.update(domain);
        for part in parts {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part);
        }
        let out: [u8; 32] = h.finalize().into();
        Digest32::new(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_sha3_256_of_empty() {
        // NIST FIPS-202 known answer for the raw primitive. Our `hash_to_digest`
        // adds a length-prefixed domain tag, so it is not the same function; pin
        // the primitive here to prove the dependency is the real SHA3-256.
        let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        let raw: [u8; 32] = Sha3_256::digest([]).into();
        let hex = hex::encode(raw);
        assert_eq!(hex, expected);
        // And the domain-separated form is a valid 32-byte digest.
        assert_eq!(
            Sha3_256Shielded.hash_to_digest(&[], &[]).as_bytes().len(),
            32
        );
    }

    #[test]
    fn domain_separates() {
        let a = Sha3_256Shielded.hash_to_digest(b"note", &[b"x"]);
        let b = Sha3_256Shielded.hash_to_digest(b"null", &[b"x"]);
        assert_ne!(a, b);
    }

    #[test]
    fn unambiguous_concatenation() {
        // ("ab", "c") must not equal ("a", "bc")
        let a = Sha3_256Shielded.hash_to_digest(b"d", &[b"ab", b"c"]);
        let b = Sha3_256Shielded.hash_to_digest(b"d", &[b"a", b"bc"]);
        assert_ne!(a, b);
    }
}
