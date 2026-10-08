//! Deterministic shielded fixtures shared by the prover's tests.
//!
//! Test-only. Production `rho`, `psi` and `sk_d` come from a CSPRNG in the
//! wallet; these exist so circuit tests can build real, self-consistent notes
//! without a random source, and so the same fixture is not reimplemented per
//! module (a drifted copy is how a test starts passing against the wrong note).
//!
//! Built for the crate's own tests and for downstream crates that enable the
//! `testkit` feature; see the module declaration in `lib.rs`.

// Fixtures assert their own preconditions with `expect`: a fixture that fails
// should say so loudly at the call site rather than return a `Result` every
// caller is obliged to thread through a test body. The panics are the point,
// so `missing_panics_doc` is suppressed rather than documented per function —
// every function in this file panics on a malformed fixture, and saying so
// twenty times would obscure the one thing each one actually means.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::whir::F;

use crate::commitment_gadget::{append_to_frontier, frontier_from_leaves, FrontierWitness};
use crate::nullifier_gadget::NullifierWitness;
use pq_hash::{Digest32, MerkleRoot, Poseidon2Commitment, Poseidon2Shielded};
use shielded::keys::derive_spend_pk;
use shielded::tree::CommitmentTree;
use shielded::{Note, NullifierMap, NullifierRoots, Transfer, TransferPublic};

// ── Minimal AIR for WHIR proof vectors ───────────────────────────────────────
//
// Lives here rather than in `whir.rs`'s test module so the vector generators in
// `tests/` can produce real proofs with it. One AIR, shared deliberately: a
// generator with its own copy of the constraints could drift from the one the
// prover tests exercise, and the vectors would pin a relation nobody proves.
/// Fibonacci AIR: `a' = a + b`, `b' = a + 2b`, with the *final* `a` exposed
/// as the public output.
///
/// The public value is bound by a constraint rather than a cell pin, because
/// univariate STARKs reject boundary cell pins.
#[derive(Clone, Copy, Debug)]
pub struct FibAir;

impl<F> BaseAir<F> for FibAir {
    fn width(&self) -> usize {
        2
    }

    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder> Air<AB> for FibAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
        let (a_next, b_next) = (main.next_slice()[0], main.next_slice()[1]);
        let two = AB::F::ONE + AB::F::ONE;
        let out: AB::Expr = builder.public_values()[0].into();

        builder.when_first_row().assert_eq(a, AB::F::ONE);
        builder.when_first_row().assert_eq(b, AB::F::ONE);
        builder.when_transition().assert_eq(a + b, a_next);
        builder.when_transition().assert_eq(a + b * two, b_next);
        builder.when_last_row().assert_eq(a, out);
    }
}

/// Build the Fibonacci trace and the public output it proves.
///
/// Row `i` is `(a_i, b_i)` following the AIR's own recurrence, so the trace
/// and the constraints are written from the same rule.
#[must_use]
pub fn fib(len: usize) -> (RowMajorMatrix<F>, Vec<F>) {
    let mut values = vec![F::ONE; len * 2];
    for i in 1..len {
        let a = values[(i - 1) * 2];
        let b = values[(i - 1) * 2 + 1];
        values[i * 2] = a + b;
        values[i * 2 + 1] = a + (b + b);
    }
    let last_row_a = values[values.len() - 2];
    (RowMajorMatrix::new(values, 2), vec![last_row_a])
}

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
    let pk_d = derive_spend_pk(&Poseidon2Shielded, &sk_d);
    let note = Note::new(
        value,
        seed(byte.wrapping_add(100)),
        seed(byte.wrapping_add(200)),
        pk_d,
    );
    (note, sk_d)
}

/// The commitment-tree hasher the fixtures use (D-088: Poseidon2).
#[must_use]
pub fn commitment_hasher() -> Poseidon2Commitment {
    Poseidon2Commitment::default()
}

/// A tree holding `notes`, with a leaf-to-root sibling path for each.
///
/// All leaves are appended before any path is captured: a path taken mid-append
/// reflects a different root and every circuit using it would be rejected.
#[must_use]
pub fn tree_with(notes: &[Note]) -> (CommitmentTree<Poseidon2Commitment>, Vec<Vec<Digest32>>) {
    let hasher = commitment_hasher();
    let mut tree = CommitmentTree::new(hasher.clone());
    for note in notes {
        tree.append(&note.commit(&hasher));
    }
    let paths = (0..notes.len())
        .map(|i| tree.path(i).expect("path exists").siblings)
        .collect();
    (tree, paths)
}

/// The frontier witness of `tree` - the state the in-circuit append gadget
/// starts from (D-088).
#[must_use]
pub fn frontier_of(tree: &CommitmentTree<Poseidon2Commitment>) -> FrontierWitness {
    frontier_from_leaves(&commitment_hasher(), tree.leaves())
}

/// The public statement and per-spend nullifier witnesses, from one map walk.
///
/// Delegates to [`crate::client::nullifier_transition`] rather than
/// reimplementing the walk. Two copies of this logic is how a test starts
/// passing against a state transition the production prover would not
/// produce; one implementation means the fixture cannot drift.
///
/// # Panics
///
/// Panics if a fixture repeats a nullifier, or if the map is denser than the
/// circuit's [`crate::nullifier_gadget::FOLD_DEPTH`] allows. Both are fixture
/// bugs, not runtime conditions a test should swallow.
#[must_use]
pub fn nullifier_transition(
    transfer: &Transfer<'_>,
    map: &mut NullifierMap<Poseidon2Commitment>,
) -> (NullifierRoots, Vec<NullifierWitness>) {
    crate::client::nullifier_transition(transfer, map)
        .expect("fixture must produce a valid nullifier transition")
}

/// [`nullifier_transition`] over a fresh empty map, returning the full
/// [`TransferPublic`] ready for the circuit, plus the frontier witness the
/// in-circuit append starts from.
///
/// The tree is the source of truth for both roots: `root` is its current root
/// and `root_after` is its root with the transfer's output leaves appended - the
/// same derivation a real prover does against the node's tree service.
#[must_use]
pub fn public_and_witnesses(
    transfer: &Transfer<'_>,
    tree: &CommitmentTree<Poseidon2Commitment>,
) -> (TransferPublic, Vec<NullifierWitness>, FrontierWitness) {
    public_and_witnesses_from(transfer, tree, NullifierMap::new(Poseidon2Commitment::default()))
}

/// [`public_and_witnesses`] over a map that already holds prior spends.
///
/// Taking the map as an argument is what lets a test start from a *non-empty*
/// nullifier set, so the absence fold is not trivially the empty-subtree root.
#[must_use]
pub fn public_and_witnesses_from(
    transfer: &Transfer<'_>,
    tree: &CommitmentTree<Poseidon2Commitment>,
    mut map: NullifierMap<Poseidon2Commitment>,
) -> (TransferPublic, Vec<NullifierWitness>, FrontierWitness) {
    let hasher = commitment_hasher();
    let (roots, witnesses) = nullifier_transition(transfer, &mut map);
    let root = tree.root();
    // root_after: fold the frontier after appending every output leaf.
    let mut frontier = frontier_of(tree);
    for note in &transfer.outputs {
        let leaf = note.commit(&hasher);
        append_to_frontier(&hasher, &mut frontier, &Digest32::new(*leaf.as_bytes()))
            .expect("fixture tree cannot be full");
    }
    let root_after = crate::commitment_gadget::fold_to_root(&hasher, &frontier);
    let public = transfer.public(
        &hasher,
        &Poseidon2Shielded,
        root,
        MerkleRoot::from_digest(root_after),
        roots,
    );
    (public, witnesses, frontier_of(tree))
}
