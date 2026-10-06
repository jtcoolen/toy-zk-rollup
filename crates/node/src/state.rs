//! Canonical pool state: the two trees the rollup is made of.
//!
//! # Why the node holds trees and the contract holds roots
//!
//! The settlement contract stores two `bytes32` values and nothing else that
//! matters. The node stores the structures those roots commit to: an
//! append-only note tree and a nullifier map. That split is deliberate and
//! asymmetric:
//!
//! * the node can rebuild its trees by replaying the contract's published
//!   `BlockApplied` events (every output commitment and nullifier is in the
//!   verified statement);
//! * the contract cannot rebuild anything from a root — a root is a digest, not
//!   a data structure.
//!
//! So the node is a service that can be replaced, and the contract is the
//! ledger that cannot. Losing the node costs availability until another is
//! synced; losing the contract costs the pool.
//!
//! # Replay, not snapshot
//!
//! State advances by applying transfers, never by assignment. There is no
//! `set_root`: the only way a root changes is that notes were appended or
//! nullifiers inserted, and both operations recompute the root from the
//! structure. A bug that "fixes" a root by writing it would have nowhere to
//! live here.

use pq_hash::{Keccak256Commitment, MerkleRoot, NoteHash, Nullifier, Poseidon2Commitment};
use shielded::nullifier_tree::NullifierMap;
use shielded::tree::CommitmentTree;

use crate::tx::TxError;

/// The pool's canonical state at a point in the chain.
///
/// The two trees use different hashers, and the split is the whole point of
/// D-088: the commitment tree is Poseidon2 because the transfer circuit proves
/// its own appends in-circuit (one permutation per row instead of twenty-four
/// Keccak rounds), so the contract stores the attested root instead of
/// re-deriving it, and the hasher behind the tree is the circuit's choice, not
/// the EVM's. The nullifier map stays Keccak-256: its absence fold was built
/// and measured there, and nothing about D-088 asks it to move. The shielded
/// layer's SHA3-256 never appears in a tree; it is confined to note and
/// nullifier derivation, off-tree.
#[derive(Clone)]
pub struct PoolState {
    /// The append-only note commitment tree (Poseidon2, D-088).
    tree: CommitmentTree<Poseidon2Commitment>,
    /// The nullifier map: which nullifiers have been spent.
    nullifiers: NullifierMap<Keccak256Commitment>,
    /// Number of blocks applied to reach this state.
    block_number: u64,
}

/// Errors from a state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// A nullifier was already spent.
    DoubleSpend(Nullifier),
    /// The transfer's claimed `root` is not this state's root.
    StaleRoot {
        /// What the state actually is at.
        actual: MerkleRoot,
        /// What the transfer claimed.
        claimed: MerkleRoot,
    },
    /// The transfer's nullifier-root chain does not start where this state is.
    StaleNullifierRoot {
        /// What the state actually is at.
        actual: MerkleRoot,
        /// What the transfer claimed.
        claimed: MerkleRoot,
    },
    /// Value is not conserved.
    Imbalanced,
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DoubleSpend(_) => write!(f, "nullifier already spent"),
            Self::StaleRoot { actual, claimed } => {
                write!(
                    f,
                    "transfer witnessed against root {}, but the pool is at {}",
                    claimed.to_hex(),
                    actual.to_hex()
                )
            }
            Self::StaleNullifierRoot { actual, claimed } => {
                write!(
                    f,
                    "transfer witnessed against nullifier root {}, but the pool is at {}",
                    claimed.to_hex(),
                    actual.to_hex()
                )
            }
            Self::Imbalanced => write!(f, "transfer does not conserve value"),
        }
    }
}

impl std::error::Error for StateError {}

impl PoolState {
    /// The genesis state: both trees empty.
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            tree: CommitmentTree::new(Poseidon2Commitment::default()),
            nullifiers: NullifierMap::new(Keccak256Commitment),
            block_number: 0,
        }
    }

    /// A genesis state whose tree already holds `notes`.
    ///
    /// This is the initial distribution: the notes every transfer in the
    /// pool will witness against. It exists because a transfer's `root` is a
    /// commitment to a tree that *already contains* the note being spent, so
    /// a pool starting from an empty tree could never admit a single transfer.
    ///
    /// Funding is an append, not a root assignment. There is no `set_root`:
    /// the root here is computed from the notes, the same way every later root
    /// is computed from appends, so a funded genesis and a genesis that grew
    /// by appending produce identical roots for identical contents.
    #[must_use]
    pub fn funded(notes: impl IntoIterator<Item = NoteHash>) -> Self {
        let mut state = Self::genesis();
        for note in notes {
            state.tree.append(&note);
        }
        state
    }

    /// The current note commitment tree root.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        self.tree.root()
    }

    /// The current nullifier map root.
    #[must_use]
    pub fn nullifier_root(&self) -> MerkleRoot {
        self.nullifiers.root()
    }

    /// Number of blocks applied.
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    /// Number of notes in the tree.
    #[must_use]
    pub const fn note_count(&self) -> usize {
        self.tree.len()
    }

    /// Number of nullifiers recorded.
    #[must_use]
    pub fn spent_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Whether `nullifier` has been spent.
    #[must_use]
    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.is_spent(nullifier)
    }

    /// A clone of the nullifier map.
    ///
    /// The sequencer needs the map itself — not just its root — to maintain a
    /// *pending* projection that chains the mempool's nullifiers ahead of the
    /// committed state. Handing out a clone keeps the map's internals private
    /// while giving the sequencer a structure it can insert into and recompute
    /// roots from.
    #[must_use]
    pub fn nullifier_map(&self) -> NullifierMap<Keccak256Commitment> {
        self.nullifiers.clone()
    }

    /// Check that a transfer's claimed roots match this state, without
    /// mutating anything.
    ///
    /// This is the admission test, run before a prover is handed work. It is
    /// separate from [`Self::apply`] because the prover needs the check to
    /// happen *before* it spends seconds proving, and because a batch is
    /// admitted transfer-by-transfer while it is applied all at once.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::DoubleSpend`] if any nullifier is already spent,
    /// or [`StateError::StaleRoot`] / [`StateError::StaleNullifierRoot`] if
    /// the transfer was witnessed against a different state.
    pub fn check_admit(&self, public: &shielded::TransferPublic) -> Result<(), StateError> {
        self.check_admit_against(public, self.root(), self.nullifier_root())
    }

    /// Check a transfer against supplied tree and nullifier roots.
    ///
    /// Taking both roots as arguments rather than reading them from `self` is
    /// what lets one check serve two cases that genuinely differ:
    ///
    /// * admission against the **committed** state (this crate's
    ///   [`Self::check_admit`]), and
    /// * admission against the sequencer's **pending** projections, which
    ///   already contain the mempool's outputs and nullifiers.
    ///
    /// Since D-088 both roots chain transfer by transfer within a batch: each
    /// transfer attests the root its own appends produce (`root_after`), and
    /// the block circuit pins each child's `root` to its predecessor's
    /// `root_after`, so the honest `before` for a queued transfer is the
    /// projection's root, not the committed one. A check hardwired to one
    /// snapshot could express neither case.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::check_admit`], with the arguments
    /// standing in for the committed roots.
    ///
    /// [`Self::check_admit`]: PoolState::check_admit
    pub fn check_admit_against(
        &self,
        public: &shielded::TransferPublic,
        expected_tree_root: MerkleRoot,
        expected_nullifier_root: MerkleRoot,
    ) -> Result<(), StateError> {
        if public.root != expected_tree_root {
            return Err(StateError::StaleRoot {
                actual: expected_tree_root,
                claimed: public.root,
            });
        }
        if public.nullifier_roots.before != expected_nullifier_root {
            return Err(StateError::StaleNullifierRoot {
                actual: expected_nullifier_root,
                claimed: public.nullifier_roots.before,
            });
        }
        for nf in &public.nullifiers {
            if self.nullifiers.is_spent(nf) {
                return Err(StateError::DoubleSpend(*nf));
            }
        }
        Ok(())
    }

    /// Apply a transfer's public effects, advancing both roots.
    ///
    /// The caller has already verified the proof; this records what the proof
    /// established. The roots the transfer claims are *checked*, not trusted:
    /// if the `after` roots do not match what the insertions actually produce,
    /// that is a bug in the prover or the statement, and it surfaces here as
    /// an error rather than silently corrupting the tree.
    ///
    /// # Atomicity
    ///
    /// Validation happens entirely before mutation, so a rejected transfer
    /// leaves the state exactly as it was found. This matters: the block driver
    /// applies transfers one at a time, and a half-applied transfer — some
    /// nullifiers inserted, outputs not appended — would desynchronize the two
    /// trees and leave the node unable to build or verify the next block.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::DoubleSpend`] if a nullifier is already spent or
    /// repeats within this transfer, or [`StateError::StaleNullifierRoot`] if
    /// the claimed `after` root does not match the map's recomputed root.
    pub fn apply(&mut self, public: &shielded::TransferPublic) -> Result<(), StateError> {
        // Check the whole batch before touching anything. Inserting as we check
        // would leave earlier nullifiers spent when a later one collides.
        //
        // `seen` catches a transfer that lists the same nullifier twice: against
        // the live map each lookup passes, but the second spend is still a
        // replay, and a set-based insert would silently deduplicate it rather
        // than reject it.
        let mut seen: std::collections::HashSet<Nullifier> =
            std::collections::HashSet::with_capacity(public.nullifiers.len());
        for nf in &public.nullifiers {
            if self.nullifiers.is_spent(nf) || !seen.insert(*nf) {
                return Err(StateError::DoubleSpend(*nf));
            }
        }

        // Compute the resulting root on a probe copy. The map's root is a
        // function of the spent *set*, not of insertion order, so the probe's
        // root is exactly what the real insertions would produce — and if it
        // disagrees with the claim, the real map never moves.
        let mut probe = self.nullifiers.clone();
        for nf in &public.nullifiers {
            // Always returns `true`: the duplicate check above guarantees none
            // of these is already in the map.
            let _ = probe.insert(nf);
        }
        if probe.root() != public.nullifier_roots.after {
            return Err(StateError::StaleNullifierRoot {
                actual: probe.root(),
                claimed: public.nullifier_roots.after,
            });
        }

        // Same probe discipline for the commitment tree: the proof attests the
        // append (D-088), so a claimed `root_after` that the appends do not
        // produce means the statement and the state disagree, and the state
        // must not move.
        let mut tree_probe = self.tree.clone();
        for out in &public.outputs {
            tree_probe.append(out);
        }
        if tree_probe.root() != public.root_after {
            return Err(StateError::StaleRoot {
                actual: tree_probe.root(),
                claimed: public.root_after,
            });
        }

        self.nullifiers = probe;
        self.tree = tree_probe;
        Ok(())
    }

    /// A clone of the commitment tree.
    ///
    /// The sequencer maintains a *pending* projection of the tree exactly the
    /// way it projects the nullifier map (see `sequencer`): queued transfers
    /// chain from each other's `root_after`, so admission and proving run
    /// against the projection, not the committed state. Handing out a clone
    /// keeps the tree's internals private while giving the sequencer a
    /// structure it can append to and recompute roots from.
    #[must_use]
    pub fn commitment_tree(&self) -> CommitmentTree<Poseidon2Commitment> {
        self.tree.clone()
    }

    /// Advance the block counter. Called once per applied block.
    pub const fn commit_block(&mut self) {
        self.block_number += 1;
    }

    /// A sibling path for leaf `index`, for building a spend witness.
    ///
    /// # Errors
    ///
    /// Returns [`TxError::TooLarge`] if `index` is out of range — the same
    /// "the caller asked for something that does not exist" class the wire
    /// format rejects.
    pub fn path(&self, index: usize) -> Result<shielded::tree::MembershipPath, TxError> {
        self.tree.path(index).ok_or(TxError::TooLarge)
    }

    /// A non-inclusion witness for `nullifier`, for building a transfer.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::DoubleSpend`] if the nullifier is already spent,
    /// which is exactly the case in which no absence witness exists.
    pub fn non_inclusion_witness(
        &self,
        nullifier: &Nullifier,
    ) -> Result<shielded::NonInclusionWitness, StateError> {
        self.nullifiers
            .non_inclusion_witness(nullifier)
            .ok_or(StateError::DoubleSpend(*nullifier))
    }
}

impl Default for PoolState {
    fn default() -> Self {
        Self::genesis()
    }
}

impl core::fmt::Debug for PoolState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolState")
            .field("block_number", &self.block_number)
            .field("notes", &self.tree.len())
            .field("spent", &self.nullifiers.len())
            .field("root", &self.root().to_hex())
            .field("nullifier_root", &self.nullifier_root().to_hex())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_hash::{Digest32, NoteHash};
    use shielded::NullifierRoots;

    fn nf(byte: u8) -> Nullifier {
        Nullifier::from_digest(Digest32::new([byte; 32]))
    }

    fn note_hash(byte: u8) -> NoteHash {
        NoteHash::from_digest(Digest32::new([byte; 32]))
    }

    /// A public statement whose roots are taken from the live state, as a real
    /// prover would build it.
    fn statement_for(
        state: &PoolState,
        nullifiers: Vec<Nullifier>,
        outputs: Vec<NoteHash>,
        fee: u64,
    ) -> shielded::TransferPublic {
        let mut map_probe = state.nullifier_root();
        // Compute the `after` root the same way `apply` will, by inserting
        // into a clone. Doing it here rather than hardcoding keeps the fixture
        // honest: if the insert logic changes, this changes with it.
        let mut clone_state = state.clone();
        for n in &nullifiers {
            let _ = clone_state.nullifiers.insert(n);
            map_probe = clone_state.nullifiers.root();
        }
        // root_after the same way: append the outputs to a clone of the tree.
        let mut tree_probe = state.tree.clone();
        for o in &outputs {
            tree_probe.append(o);
        }
        shielded::TransferPublic {
            nullifiers,
            outputs,
            root: state.root(),
            root_after: tree_probe.root(),
            nullifier_roots: NullifierRoots {
                before: state.nullifier_root(),
                after: map_probe,
            },
            fee,
        }
    }

    #[test]
    fn genesis_has_empty_roots() {
        let state = PoolState::genesis();
        assert_eq!(state.note_count(), 0);
        assert_eq!(state.spent_count(), 0);
        assert_eq!(state.block_number(), 0);
        assert_eq!(state.root(), state.tree.empty_root());
    }

    #[test]
    fn applying_a_transfer_advances_both_roots() {
        let mut state = PoolState::genesis();
        let public = statement_for(&state, vec![nf(1)], vec![note_hash(9)], 10);
        let before = state.root();
        let nf_before = state.nullifier_root();

        state.apply(&public).expect("applies");
        state.commit_block();

        assert_ne!(state.root(), before, "outputs must move the tree root");
        assert_ne!(
            state.nullifier_root(),
            nf_before,
            "nullifiers must move the map root"
        );
        assert_eq!(state.note_count(), 1);
        assert_eq!(state.spent_count(), 1);
        assert!(state.is_spent(&nf(1)));
        assert_eq!(state.block_number(), 1);
    }

    /// The replay case, stated directly: the same nullifier twice must fail,
    /// and fail on the second application, not the first.
    #[test]
    fn a_replayed_nullifier_is_rejected() {
        let mut state = PoolState::genesis();
        let public = statement_for(&state, vec![nf(1)], vec![note_hash(9)], 10);
        state.apply(&public).expect("first applies");

        // Rebuild the same statement against the *new* state so the only
        // difference is the replayed nullifier.
        let mut tree_probe = state.tree.clone();
        tree_probe.append(&note_hash(10));
        let replay = shielded::TransferPublic {
            nullifiers: public.nullifiers.clone(),
            outputs: vec![note_hash(10)],
            root: state.root(),
            root_after: tree_probe.root(),
            nullifier_roots: NullifierRoots {
                before: state.nullifier_root(),
                after: state.nullifier_root(),
            },
            fee: 10,
        };
        assert_eq!(
            state.apply(&replay),
            Err(StateError::DoubleSpend(nf(1))),
            "the second spend of the same nullifier must be rejected"
        );
    }

    #[test]
    fn admission_rejects_a_stale_tree_root() {
        let mut state = PoolState::genesis();
        let mut public = statement_for(&state, vec![nf(1)], vec![note_hash(9)], 10);
        state.apply(&public).expect("applies");

        // A transfer witnessed against the *old* root.
        public.root = PoolState::genesis().root();
        assert!(matches!(
            state.check_admit(&public),
            Err(StateError::StaleRoot { .. })
        ));
    }

    #[test]
    fn admission_rejects_a_stale_nullifier_root() {
        let mut state = PoolState::genesis();
        let mut public = statement_for(&state, vec![nf(1)], vec![note_hash(9)], 10);
        state.apply(&public).expect("applies");

        // Sync the tree root to the *new* state so the tree-root check passes,
        // isolating the nullifier-root check. Without this the earlier
        // `StaleRoot` check fires first and the test would pass for the wrong
        // reason — or, worse, stop covering this branch silently.
        public.root = state.root();
        public.nullifier_roots.before = PoolState::genesis().nullifier_root();
        assert!(matches!(
            state.check_admit(&public),
            Err(StateError::StaleNullifierRoot { .. })
        ));
    }

    /// `apply` checks the claimed `after` root rather than trusting it. A
    /// statement that names a root the inserts do not produce is an error.
    #[test]
    fn apply_rejects_a_claimed_after_root_that_does_not_match() {
        let mut state = PoolState::genesis();
        let mut public = statement_for(&state, vec![nf(1)], vec![note_hash(9)], 10);
        public.nullifier_roots.after = PoolState::genesis().nullifier_root();
        assert!(matches!(
            state.apply(&public),
            Err(StateError::StaleNullifierRoot { .. })
        ));
        // And the state was not partially advanced.
        assert_eq!(state.spent_count(), 0, "a rejected apply must not mutate");
    }

    /// A transfer that lists the same nullifier twice is a replay against
    /// itself: each lookup passes against the live map, so the duplicate must
    /// be caught by the intra-batch check rather than by the map.
    #[test]
    fn a_transfer_cannot_spend_the_same_nullifier_twice() {
        let mut state = PoolState::genesis();
        let single = statement_for(&state, vec![nf(1)], vec![note_hash(9)], 10);
        let dup = shielded::TransferPublic {
            nullifiers: vec![nf(1), nf(1)],
            outputs: single.outputs.clone(),
            root: state.root(),
            root_after: single.root_after,
            // Reuse the single-insert `after`. A set-based insert would
            // deduplicate the repeat and land on exactly this root, so the
            // root check would pass and the transfer would sail through. The
            // intra-batch duplicate check is what stops it, and this fixture
            // is built so that only that check can.
            nullifier_roots: single.nullifier_roots,
            fee: single.fee,
        };
        assert_eq!(
            state.apply(&dup),
            Err(StateError::DoubleSpend(nf(1))),
            "a self-duplicated nullifier must be rejected"
        );
        assert_eq!(state.spent_count(), 0, "and must not mutate");
    }

    #[test]
    fn paths_and_witnesses_are_available() {
        let mut state = PoolState::genesis();
        let public = statement_for(&state, vec![nf(1)], vec![note_hash(9), note_hash(10)], 10);
        state.apply(&public).expect("applies");

        assert!(state.path(0).is_ok());
        assert!(state.path(1).is_ok());
        assert!(state.path(2).is_err(), "no leaf 2 exists");
        // A fresh nullifier has an absence witness; a spent one does not.
        assert!(state.non_inclusion_witness(&nf(50)).is_ok());
        assert!(state.non_inclusion_witness(&nf(1)).is_err());
    }

    /// Roots are deterministic: two nodes applying the same transfers in the
    /// same order land on the same roots. Without this, no two honest nodes
    /// could agree.
    #[test]
    fn state_is_deterministic() {
        let build = || {
            let mut s = PoolState::genesis();
            for i in 0..4u8 {
                let p = statement_for(&s, vec![nf(i)], vec![note_hash(i + 100)], 1);
                s.apply(&p).expect("applies");
                s.commit_block();
            }
            s
        };
        let a = build();
        let b = build();
        assert_eq!(a.root(), b.root());
        assert_eq!(a.nullifier_root(), b.nullifier_root());
        assert_eq!(a.block_number(), b.block_number());
    }
}
