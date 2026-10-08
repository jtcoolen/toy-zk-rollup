//! The client side of the protocol: build and prove one transfer.
//!
//! # Why this lives in the prover crate and not the wallet
//!
//! Because it is the same code. A wallet that proved transfers differently
//! from the node's reference implementation would produce proofs the node
//! rejects, and debugging that across a process boundary is miserable. Keeping
//! the canonical client here means the wallet is a UI over these functions,
//! and the demo's integration tests exercise the exact path a real wallet
//! takes.
//!
//! What the wallet adds on top is custody: keeping `sk_d` off disk, wrapping it
//! in `WebCrypto`, never handing it to anything but this function.
//!
//! # What leaves the client
//!
//! Only [`ClientTransferArtifacts`]: the proof, the verifier, the statement,
//! and the public statement. No note, no `sk_d`, no `rho`, no `psi`. The
//! membership path stays local too — it is consumed by the circuit and never
//! transmitted, because the proof already attests to it.
//!
//! # The map the client walks
//!
//! [`prove_client_transfer`] takes a [`NullifierMap`] and *advances* it. In
//! the demo the client and the sequencer share one map because they are one
//! process. In production the client maintains its own view from the chain's
//! published nullifiers, and the sequencer maintains its own; they agree
//! because both derive from the same verified statements, not because they
//! share memory.

use std::error::Error;

use pq_hash::{Digest32, MerkleRoot, Poseidon2Commitment, Poseidon2Shielded};
use shielded::transfer::Spend;
use shielded::tree::CommitmentTree;
use shielded::{Note, NullifierMap, Transfer, TransferPublic};

use crate::commitment_gadget::{append_to_frontier, fold_to_root, frontier_from_leaves};
use crate::nullifier_gadget::NullifierWitness;
use crate::transfer::{build_transfer_circuit, settle_transfer_circuit_with};
use crate::whir_recursion::{InnerWhirConfig, F};

/// One client's transfer witness, as it exists on the spender's machine.
///
/// Every field here is secret except `index`. That is deliberate: the note's
/// value and randomness and the spending key are exactly what the shielded
/// layer protects, and the circuit consumes them without any of them appearing
/// in the statement.
#[derive(Debug)]
pub struct ClientSpec<'a> {
    /// The note being spent.
    pub note: &'a Note,
    /// The spending key that opens it.
    pub sk_d: &'a [u8; 32],
    /// Sibling digests from the note's leaf to the tree root.
    pub path: &'a [pq_hash::Digest32],
    /// The note's leaf index in the commitment tree.
    pub index: usize,
    /// The output note the transfer creates.
    ///
    /// Built by the caller, not here, because its `rho` and `psi` must come
    /// from a CSPRNG owned by the wallet. Deriving them from the spent note's
    /// randomness — the obvious shortcut — would make the two notes linkable
    /// by anyone who learns one of them, quietly breaking the hiding property
    /// for every transfer the shortcut touches.
    pub output: &'a Note,
    /// The fee to pay.
    pub fee: u64,
}

/// What a client's proving run produces.
///
/// The `CircuitVerifier` is part of the output rather than an internal detail
/// because the block circuit takes each child's relation from the *retained
/// verifier*, not from anything the proof asserts. A proof without its
/// verifier cannot be batched.
pub struct ClientTransferArtifacts {
    /// The verifier retained from the proving run.
    pub verifier: p3_circuit_prover::CircuitVerifier<InnerWhirConfig>,
    /// The transfer proof, under the inner (Poseidon2) WHIR config.
    pub proof: p3_circuit_prover::BatchStarkProof<InnerWhirConfig>,
    /// The statement proved, as base-field limbs.
    pub statement: Vec<F>,
    /// The public statement, for the node's admission check.
    pub public: TransferPublic,
    /// The per-spend nullifier witnesses, kept for audit.
    pub witnesses: Vec<NullifierWitness>,
}

impl core::fmt::Debug for ClientTransferArtifacts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientTransferArtifacts")
            .field("statement_len", &self.statement.len())
            .field("nullifiers", &self.public.nullifiers.len())
            .field("outputs", &self.public.outputs.len())
            .field("fee", &self.public.fee)
            .finish_non_exhaustive()
    }
}

/// Build and prove one client transfer, as a spender would on their own
/// machine, returning the artefacts a block consumes.
///
/// `map` is advanced by this call: each spend's nullifier is inserted after
/// its absence witness is drawn. Passing the same map across several calls is
/// what makes the transfers transitions of *one* nullifier trie, which is the
/// only thing the block's chain constraint can mean.
///
/// The proof is verified before it is returned. A client that handed an
/// invalid proof to the network would just have wasted its own CPU, and
/// failing here means the bug surfaces where it can be debugged.
///
/// # Errors
///
/// Returns an error if the transfer's balance does not balance, if a
/// nullifier's absence witness cannot be built (already spent, or the map is
/// denser than the circuit's fold depth allows), or if the circuit cannot be
/// witnessed or proven.
pub fn prove_client_transfer(
    inner: &InnerWhirConfig,
    spec: &ClientSpec<'_>,
    tree: &CommitmentTree<Poseidon2Commitment>,
    map: &mut NullifierMap<Poseidon2Commitment>,
) -> Result<ClientTransferArtifacts, Box<dyn Error>> {
    let spend = Spend {
        note: spec.note,
        sk_d: spec.sk_d,
        path: spec.path,
        index: spec.index,
    };
    let transfer = Transfer {
        spends: vec![spend],
        outputs: vec![*spec.output],
        fee: spec.fee,
    };
    transfer
        .check_balance()
        .map_err(|e| -> Box<dyn Error> { Box::new(e) })?;

    // The roots and the witnesses come out of one walk of the shared map, so
    // this client's `before` is whatever the previous client left behind.
    let (nullifier_roots, witnesses) = nullifier_transition(&transfer, map)?;
    // The commitment-tree roots come from the tree, not the caller: `root` is
    // its current root and `root_after` is its root with this transfer's output
    // leaves folded in, computed with the same frontier arithmetic the circuit
    // re-derives (D-088).
    let hasher = Poseidon2Commitment::default();
    let root = tree.root();
    // The circuit starts from the *pre-append* frontier and re-derives each
    // step itself; the post-append fold here only computes the claimed
    // `root_after`, which the circuit then pins against its own walk.
    let frontier = frontier_from_leaves(&hasher, tree.leaves());
    let mut frontier_after = frontier.clone();
    for note in &transfer.outputs {
        let leaf = note.commit(&hasher);
        append_to_frontier(
            &hasher,
            &mut frontier_after,
            &Digest32::new(*leaf.as_bytes()),
        )
        .map_err(|e| -> Box<dyn Error> { Box::new(std::io::Error::other(e)) })?;
    }
    let root_after = fold_to_root(&hasher, &frontier_after);
    let public = transfer.public(
        &hasher,
        &Poseidon2Shielded,
        root,
        MerkleRoot::from_digest(root_after),
        nullifier_roots,
    );
    let tc = build_transfer_circuit(&transfer, &public, &witnesses, &frontier)?;
    let (proof, verifier) = settle_transfer_circuit_with(&tc, inner.clone())?;
    verifier.verify(&proof, tc.statement())?;
    Ok(ClientTransferArtifacts {
        verifier,
        proof,
        statement: tc.statement().to_vec(),
        public,
        witnesses,
    })
}

/// The public statement and per-spend nullifier witnesses, from one map walk.
///
/// These must be built together. The roots and the witnesses are two views of
/// a single state transition: `before` is the map root on entry, each witness
/// is the absence proof at the state it was drawn from, and `after` is the
/// root on exit. Building them from separate walks is how they would drift
/// apart — and a drifted pair makes a transfer unwitnessable rather than
/// accepted, which is the safe direction but a confusing one to debug.
///
/// # Errors
///
/// Returns an error if a nullifier is already spent (no absence witness
/// exists) or if the map is denser than the circuit's
/// [`crate::nullifier_gadget::FOLD_DEPTH`] allows.
pub fn nullifier_transition(
    transfer: &Transfer<'_>,
    map: &mut NullifierMap<Poseidon2Commitment>,
) -> Result<(shielded::NullifierRoots, Vec<NullifierWitness>), Box<dyn Error>> {
    let before = map.root();
    let mut witnesses = Vec::with_capacity(transfer.spends.len());
    for spend in &transfer.spends {
        let nf = spend.note.nullifier(&Poseidon2Shielded, spend.sk_d);
        let native = map
            .non_inclusion_witness(&nf)
            .ok_or("nullifier already spent: no absence witness exists")?;
        witnesses.push(crate::nullifier_gadget::prepare_witness(map, &native)?);
        if !map.insert(&nf) {
            return Err("nullifier already spent".into());
        }
    }
    Ok((
        shielded::NullifierRoots {
            before,
            after: map.root(),
        },
        witnesses,
    ))
}
