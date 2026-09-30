//! The hashing traits that separate the shielded, commitment and transcript layers.
//!
//! These traits are deliberately **not** related to one another. There is no
//! `BaseHasher` they both extend, and no blanket impl that would let one satisfy
//! the other. That is the point: the shielded layer physically cannot receive the
//! Merkle hash, and vice versa.

use crate::digest::Digest32;

/// Hash used to derive note commitments and nullifiers.
///
/// This is the privacy-critical layer. It is SHA3-256 (FIPS-202).
///
/// Implementations must be:
/// - **Preimage resistant** at 128 bits against classical *and* quantum adversaries
///   (SHA3-256: Grover halves security to 128 bits, which is the target).
/// - **Domain separated.** Implementations take a `domain` tag so a note preimage
///   can never collide with a nullifier preimage.
pub trait ShieldedHasher: Clone + Send + Sync + 'static {
    /// Hash `domain || parts` into a 32-byte digest.
    fn hash_to_digest(&self, domain: &[u8], parts: &[&[u8]]) -> Digest32;
}

/// Hash used for Merkle trees and FRI commitments that the EVM must verify.
///
/// This is Keccak-256, chosen because the EVM exposes it as precompile `0x20`
/// (~30 gas) while SHA3-256 is precompile `0x04` at a similar cost but is not
/// what Plonky3's Merkle gadgets are built on.
///
/// Keccak-256 and SHA3-256 differ only in the padding byte, so this is a gas
/// choice and not a security reduction.
pub trait CommitmentHasher: Clone + Send + Sync + 'static {
    /// Hash `parts` into a 32-byte digest.
    fn hash(&self, parts: &[&[u8]]) -> Digest32;

    /// Hash two 32-byte children into their parent node.
    ///
    /// Fixed to `H(left || right)` so the Solidity tree walker and the Rust tree
    /// agree without a spec argument.
    fn hash_pair(&self, left: &Digest32, right: &Digest32) -> Digest32 {
        self.hash(&[left.as_bytes(), right.as_bytes()])
    }
}
