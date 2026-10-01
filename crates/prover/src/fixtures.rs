//! Deterministic shielded fixtures shared by the prover's tests.
//!
//! Test-only. Production `rho`, `psi` and `sk_d` come from a CSPRNG in the
//! wallet; these exist so circuit tests can build real, self-consistent notes
//! without a random source, and so the same fixture is not reimplemented per
//! module (a drifted copy is how a test starts passing against the wrong note).

#![cfg(test)]

use pq_hash::{Digest32, Keccak256Commitment, Sha3_256Shielded};
use shielded::keys::derive_spend_pk;
use shielded::tree::CommitmentTree;
use shielded::Note;

/// A tiny deterministic byte source.
#[must_use]
pub fn seed(byte: u8) -> [u8; 32] {
    core::array::from_fn(|i| {
        let i = i as u64;
        byte.wrapping_mul(31)
            .wrapping_add(u8::try_from(i % 256).expect("mod 256 fits"))
    })
}

/// A note whose `pk_d` is the honest SHA3 derivation of `sk_d`, so the
/// circuit's ownership check has a real preimage behind it.
///
/// The three seeds are offset from `byte` so a note's `rho`, `psi` and `sk_d`
/// differ from each other and from other notes'. Offsets are wrapping: a plain
/// `+` panics on `byte + 200` in a debug build.
#[must_use]
pub fn funded_note(byte: u8, value: u64) -> (Note, [u8; 32]) {
    let sk_d = seed(byte);
    let pk_d = derive_spend_pk(&Sha3_256Shielded, &sk_d);
    let note = Note::new(
        value,
        seed(byte.wrapping_add(100)),
        seed(byte.wrapping_add(200)),
        pk_d,
    );
    (note, sk_d)
}

/// A tree holding `notes`, with a leaf-to-root sibling path for each.
///
/// All leaves are appended before any path is captured: a path taken mid-append
/// reflects a different root and every circuit using it would be rejected.
#[must_use]
pub fn tree_with(notes: &[Note]) -> (CommitmentTree<Keccak256Commitment>, Vec<Vec<Digest32>>) {
    let mut tree = CommitmentTree::new(Keccak256Commitment);
    for note in notes {
        tree.append(&note.commit(&Keccak256Commitment));
    }
    let paths = (0..notes.len())
        .map(|i| tree.path(i).expect("path exists").siblings)
        .collect();
    (tree, paths)
}
