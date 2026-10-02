//! Fixed-width digest newtypes.
//!
//! `NoteHash`, `Nullifier` and `MerkleRoot` are all 32-byte strings, but they are
//! **not interchangeable**: a nullifier is not a Merkle root, and passing one for
//! the other is exactly the class of bug that mints coins out of thin air. Each is
//! a distinct type, so the compiler refuses the mix-up.

use core::fmt;

/// A 32-byte cryptographic digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Digest32(pub(crate) [u8; 32]);

impl Digest32 {
    /// Wrap raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Truncated: full digests in logs invite correlation, and nobody debugs
        // with 64 hex characters per line.
        write!(f, "Digest({}..)", &self.to_hex()[..8])
    }
}

/// The hash of a note's preimage. Commits to value, randomness and rho.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NoteHash(pub(crate) Digest32);

/// The hash of a spending key and a rho. Marks a note as spent.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Nullifier(pub(crate) Digest32);

/// The root of the note commitment Merkle tree.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MerkleRoot(pub(crate) Digest32);

impl NoteHash {
    /// Wrap a digest produced by the shielded hasher.
    #[must_use]
    pub const fn from_digest(d: Digest32) -> Self {
        Self(d)
    }

    /// The underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Lowercase hex encoding.
    ///
    /// Re-exposed on each newtype rather than reached through `.0`: callers
    /// logging a commitment should not have to know it wraps a `Digest32`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl Nullifier {
    /// Wrap a digest produced by the shielded hasher.
    #[must_use]
    pub const fn from_digest(d: Digest32) -> Self {
        Self(d)
    }

    /// The underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Lowercase hex encoding.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl MerkleRoot {
    /// Wrap a digest produced by the commitment hasher.
    #[must_use]
    pub const fn from_digest(d: Digest32) -> Self {
        Self(d)
    }

    /// The underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Lowercase hex encoding.
    ///
    /// Re-exposed on each newtype rather than reached through `.0`: callers
    /// logging a root should not have to know it wraps a `Digest32`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl fmt::Debug for NoteHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NoteHash({}..)", &self.0.to_hex()[..8])
    }
}

impl fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nullifier({}..)", &self.0.to_hex()[..8])
    }
}

impl fmt::Debug for MerkleRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MerkleRoot({}..)", &self.0.to_hex()[..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips_shape() {
        let d = Digest32::new([0xab; 32]);
        assert_eq!(d.to_hex().len(), 64);
        assert!(d.to_hex().chars().all(|c| c == 'a' || c == 'b'));
    }

    #[test]
    fn debug_output_is_truncated() {
        let d = Digest32::new([0u8; 32]);
        let s = format!("{d:?}");
        assert_eq!(s, "Digest(00000000..)");
        assert!(!s.contains(&"0".repeat(32)));
    }
}
