//! Deterministic shielded fixtures shared by the prover's tests.
//!
//! Test-only. Production `rho`, `psi` and `sk_d` come from a CSPRNG in the
//! wallet; these exist so circuit tests can build real, self-consistent notes
//! without a random source, and so the same fixture is not reimplemented per
//! module (a drifted copy is how a test starts passing against the wrong note).

#![cfg(test)]

use crate::nullifier_gadget::NullifierWitness;
use pq_hash::{Digest32, Keccak256Commitment, MerkleRoot, Sha3_256Shielded};
use shielded::keys::derive_spend_pk;
use shielded::tree::CommitmentTree;
use shielded::{Note, NullifierMap, NullifierRoots, Transfer, TransferPublic};

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

/// The public statement and per-spend nullifier witnesses, from one map walk.
///
/// These must be built together. The roots and the witnesses are two views of a
/// single state transition: `before` is the map root on entry, each witness is
/// the absence proof at the state it was drawn from, and `after` is the root on
/// exit. Building them from separate walks is how they would drift apart — and a
/// drifted pair makes a transfer unwitnessable rather than accepted, which is
/// the safe direction but a confusing one to debug.
///
/// Mirrors what the node's prover orchestration does: walk the spends in order,
/// ask the map for the absence witness, then insert.
///
/// # Panics
///
/// Panics if a fixture repeats a nullifier, or if the map is denser than the
/// circuit's [`crate::nullifier_gadget::FOLD_DEPTH`] allows. Both are fixture
/// bugs, not runtime conditions a test should swallow.
#[must_use]
pub fn nullifier_transition(
    transfer: &Transfer<'_>,
    map: &mut NullifierMap<Keccak256Commitment>,
) -> (NullifierRoots, Vec<NullifierWitness>) {
    let before = map.root();
    let mut witnesses = Vec::with_capacity(transfer.spends.len());
    for spend in &transfer.spends {
        let nf = spend.note.nullifier(&Sha3_256Shielded, spend.sk_d);
        let native = map
            .non_inclusion_witness(&nf)
            .expect("fixture nullifiers must be distinct");
        witnesses.push(
            crate::nullifier_gadget::prepare_witness(map, &native)
                .expect("map must be sparse enough for the circuit"),
        );
        assert!(map.insert(&nf), "fixture must not repeat a nullifier");
    }
    let roots = NullifierRoots {
        before,
        after: map.root(),
    };
    (roots, witnesses)
}

/// [`nullifier_transition`] over a fresh empty map, returning the full
/// [`TransferPublic`] ready for the circuit.
#[must_use]
pub fn public_and_witnesses(
    transfer: &Transfer<'_>,
    root: MerkleRoot,
) -> (TransferPublic, Vec<NullifierWitness>) {
    public_and_witnesses_from(transfer, root, NullifierMap::new(Keccak256Commitment))
}

/// [`public_and_witnesses`] over a map that already holds prior spends.
///
/// Taking the map as an argument is what lets a test start from a *non-empty*
/// nullifier set, so the absence fold is not trivially the empty-subtree root.
#[must_use]
pub fn public_and_witnesses_from(
    transfer: &Transfer<'_>,
    root: MerkleRoot,
    mut map: NullifierMap<Keccak256Commitment>,
) -> (TransferPublic, Vec<NullifierWitness>) {
    let (roots, witnesses) = nullifier_transition(transfer, &mut map);
    let public = transfer.public(&Keccak256Commitment, &Sha3_256Shielded, root, roots);
    (public, witnesses)
}
