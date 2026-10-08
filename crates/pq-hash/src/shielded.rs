//! SHA3-256 (FIPS-202) for the shielded layer.

use sha3::{Digest as _, Sha3_256};
use crate::traits::CommitmentHasher;

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
        // the domain separation.
        //
        // Little-endian, and the circuit mirrors it as little-endian
        // (`prover::transfer::len_header`). The direction is consensus-critical
        // in both places, and a prover test pins the two framings together.
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

/// The shielded-layer hasher on Poseidon2: the same sponge the commitment
/// tree uses, applied to spend-key derivation and nullifiers.
///
/// ## Why this exists (D-092 batch 82)
///
/// SHA3-256 in-circuit costs one Keccak-f[1600] permutation per digest - a
/// table row ~200 field elements wide, and the widest instance in the client
/// proof. Poseidon2 over `KoalaBear` does the same job in one ~50-column
/// permutation row, and it is the same permutation the circuit already
/// enables for the commitment tree, so the shielded digests add no new table
/// at all. The trade is recorded: this hasher's collision bound is the
/// Poseidon2 sponge's (~96-bit classical margin at this width), not SHA3's
/// 128-bit quantum margin. The operator accepted the reduction (D-092).
///
/// ## Framing
///
/// `hash_to_digest(domain, parts)` hashes `domain || p1 || p2 || ...`
/// through the commitment sponge - no length prefixes, because every
/// consensus preimage here has fixed-length parts (domain tags are fixed
/// strings, `sk_d`/`rho`/`pk_d` are 32 bytes, amounts 8). The in-circuit
/// mirror is `prover::commitment_gadget::p2_sponge_limbs` over the same
/// limb encoding, and the prover's framing test pins the two.
#[derive(Clone, Copy, Debug, Default)]
pub struct Poseidon2Shielded;

impl ShieldedHasher for Poseidon2Shielded {
    fn hash_to_digest(&self, domain: &[u8], parts: &[&[u8]]) -> Digest32 {
        let mut all: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
        all.push(domain);
        all.extend_from_slice(parts);
        crate::Poseidon2Commitment::new().hash(&all)
    }
}

#[cfg(test)]
mod p2_tests {
    use super::*;

    #[test]
    fn domain_separates_and_is_deterministic() {
        let h = Poseidon2Shielded;
        let a = h.hash_to_digest(b"pq-rollup/spendpk/v1", &[&[7u8; 32]]);
        let b = h.hash_to_digest(b"pq-rollup/nullifier/v1", &[&[7u8; 32]]);
        assert_ne!(a, b);
        assert_eq!(a, h.hash_to_digest(b"pq-rollup/spendpk/v1", &[&[7u8; 32]]));
    }
}
