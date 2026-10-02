//! The block circuit: one proof attesting to many client transfers.
//!
//! ## Why the transfers arrive as proofs, not as witnesses
//!
//! A spend is only provable by someone holding `sk_d`: the transfer circuit
//! derives `pk_d = H(DOMAIN_PK ‖ sk_d)` and
//! `nullifier = H(DOMAIN_NULLIFIER ‖ sk_d ‖ rho)` in-circuit, and those are what
//! bind the note to its owner. A circuit that witnessed N transfers natively
//! would therefore need every spender's `sk_d` in one place — a custodial mixer
//! with extra steps. The per-transfer proof is not overhead to be optimised away;
//! it is the property being protected. Each spender proves locally, on their own
//! machine, and their secret never leaves it.
//!
//! So this module does the only thing that preserves that property at block
//! scale: it **verifies** client-produced transfer proofs inside one circuit.
//!
//! ```text
//!   spender A ──local──▶ transfer proof A ─┐
//!   spender B ──local──▶ transfer proof B ─┼─▶ block circuit ─▶ one proof ─▶ L1
//!   spender C ──local──▶ transfer proof C ─┘      (sees no sk_d)
//! ```
//!
//! ## Why verifying a transfer needs no Keccak in this circuit
//!
//! Keccak-f lives *inside* the transfer's own AIR. Verifying a transfer proof is
//! re-deriving a Poseidon2 WHIR transcript and checking a Poseidon2 Merkle cap —
//! the recursion tables, not the transfer tables. So the block circuit carries
//! Poseidon2 + recompose + statement tables only, and is itself proven under
//! either the recursion config (to chain further) or the Keccak settlement
//! config (to reach L1).
//!
//! ## Statement
//!
//! The exported statement is a shape header followed by the children's statement
//! values concatenated in order:
//!
//! ```text
//! [ n, (inputs_0, outputs_0), ..., (inputs_{n-1}, outputs_{n-1}),
//!   transfer 0: nullifiers..., outputs..., root, fee,
//!   transfer 1: nullifiers..., outputs..., root, fee, ... ]
//! ```
//!
//! The header is exported as circuit constants, so the split is **bound by the
//! proof**. The settlement contract reads it from the verified statement rather
//! than being told it: a prover cannot declare a split that makes the contract
//! read an output commitment as a nullifier, or skip a real nullifier.
//!
//! That is what the settlement layer and L1 read to apply the state update.
//!
//! ## Shared anchor
//!
//! Every child is constrained to prove against the **same** commitment root.
//! Concatenating statements without that link would let a prover assemble a
//! block from transfers witnessed against *different* tree states — each child
//! individually valid, the set collectively describing a tree that never
//! existed. The anchor equality is what makes the concatenated statement
//! describe one real state transition, so it is enforced here, not left to the
//! settlement layer.
//!
//! Pinning rather than chaining the commitment root means a note created by one
//! transfer in a block cannot be spent by another transfer in the same block.
//! That is a deliberate restriction, not an oversight: it keeps the block's
//! commitment transition trivial (`root_before == root_after`, outputs appended
//! afterwards) and removes any question about ordering semantics.
//!
//! ## Nullifier roots are chained, not pinned
//!
//! The nullifier map cannot use the same trick, because each transfer's
//! `before` and `after` genuinely differ. Instead the children are **chained**:
//! child *i*'s `nullifier_root_after` is constrained equal to child *i+1*'s
//! `nullifier_root_before`. The block therefore attests to one nullifier
//! transition, from the first child's `before` to the last child's `after`,
//! with every intermediate state pinned.
//!
//! This is what replaces the on-chain nullifier set (D-032). A replayed
//! nullifier is not caught by a contract-side lookup; it is caught because the
//! chain of roots cannot be extended — the absent-fold inside each child's
//! proof fails against the root it inherited.

use crate::whir_recursion::{Challenge, InnerWhirConfig, RecursionCircuit, WhirMmcs, DIGEST_ELEMS};
use p3_circuit::{CircuitBuilder, ExprId, NonPrimitiveOpId, StatementExport};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    poseidon2_air_builders_for_configs, recompose_preprocessor, BatchStarkProver,
    ConstraintProfile, Poseidon2SharedPreprocessor, RecomposeAirBuilder, StatementAirBuilder,
    StatementPreprocessor, StatementProver,
};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::logup::LogUpGadget;
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionConfig};
use p3_recursion::pcs::fri::MerkleCapTargets;
use p3_recursion::pcs::whir::uni::WhirUniProofTargets;
use p3_recursion::verifier::verify_trusted_p3_batch_proof_circuit;
use p3_recursion::{
    BatchOnly, PcsRecursionBackend, Poseidon2Config, ProveNextLayerParams,
    TrustedPcsRecursionBackend,
};
use std::error::Error;

use crate::whir_recursion::F;

/// Stacked-polynomial height budget for the **two-transfer** block under test.
///
/// A block's statement is the concatenation of its children's statements, so
/// more children means more claims and a higher stacked arity. The WHIR grinding
/// budget is a function of that arity, and sizing the config below what the
/// actual arity requires is a panic at prove time, not an error (D-021).
///
/// Measured budget curve: v=22->14, 23->17, 24->18, 25->19, 26->20, 27->23,
/// and v>=28 fails outright with `FoldedDomainExceedsCapacity`.
///
/// **This must be sized close to the actual stacked arity; over-provisioning is
/// NOT free.** The prover pads the polynomial to the declared height, so a
/// larger budget means a larger LDE and more proving work: the same fan-in-2
/// block took 9.2 s at v=25 and 25.1 s at v=27. Under-provisioning panics,
/// over-provisioning wastes roughly 2.7x. Each fan-in needs its own measured
/// value.
///
/// Fan-in 1 settles at v=24; fan-in 2 needs v=25.
#[cfg(test)]
const BLOCK_LOG_MAX_LDE: usize = 25;

/// Merkle cap height for the settlement layer.
///
/// **Measured: raising it makes the proof BIGGER, not smaller.** The intuition
/// that a cap shortens authentication paths is correct but incomplete here —
/// WHIR re-commits every folding round, and with a cap the commitment is a
/// `2^cap_height`-element Merkle cap serialized *per round*. At cap 8 that is
/// 256 digests per round against ~15 rounds, which swamps the path saving:
/// 767 KB at cap 0 became 905 KB at cap 8.
///
/// Cap height is therefore not a lever in this stack. It would only pay off if
/// the cap were sent once and referenced by digest, which the WHIR proof
/// format does not do.
///
/// Not `#[cfg(test)]`: `settle_block_circuit` reads it, so it is part of the
/// production configuration even though its value was chosen by measurement.
pub const BLOCK_CAP_HEIGHT: usize = 0;

/// Limbs per 32-byte hash in a transfer statement (32 bytes / 16-bit limbs).
const LIMBS_PER_HASH: usize = 16;
/// Limbs of the fee field in a transfer statement (`VALUE_LIMBS` in the
/// transfer circuit).
const FEE_LIMBS: usize = 4;

/// The shape of a transfer statement, needed to locate fields inside it.
///
/// A transfer exports, in this order:
/// `[nullifier_0…, output_0…, root, nf_root_before, nf_root_after, fee]` —
/// 16 limbs per hash, 4 for the fee. The block circuit needs this to find each
/// child's roots without guessing, so a shape that does not match the statement
/// it describes is rejected rather than silently constraining the wrong limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferShape {
    /// Number of inputs spent (one nullifier each).
    pub num_nullifiers: usize,
    /// Number of notes created (one commitment each).
    pub num_outputs: usize,
}

impl TransferShape {
    /// Total statement limbs this shape implies.
    #[must_use]
    pub const fn statement_len(&self) -> usize {
        LIMBS_PER_HASH * (self.num_nullifiers + self.num_outputs + 3) + FEE_LIMBS
    }

    /// Offset of the 16 root limbs within the statement.
    #[must_use]
    pub const fn root_offset(&self) -> usize {
        LIMBS_PER_HASH * (self.num_nullifiers + self.num_outputs)
    }

    /// Offset of the nullifier-map root *before* this transfer.
    #[must_use]
    pub const fn nullifier_before_offset(&self) -> usize {
        LIMBS_PER_HASH * (self.num_nullifiers + self.num_outputs + 1)
    }

    /// Offset of the nullifier-map root *after* this transfer.
    #[must_use]
    pub const fn nullifier_after_offset(&self) -> usize {
        LIMBS_PER_HASH * (self.num_nullifiers + self.num_outputs + 2)
    }
}

/// Width of the exported shape header for a block of `num_children` transfers:
/// one limb for the count, then `(inputs, outputs)` per transfer.
///
/// The header is part of the verified statement, so the settlement layer reads
/// the split from the proof instead of being told it.
#[must_use]
pub const fn shape_header_len(num_children: usize) -> usize {
    1 + 2 * num_children
}

/// The shape header's raw limbs: `[n, nin_0, nout_0, nin_1, nout_1, …]`.
///
/// Shared by the circuit builder, which exports these as statement constants,
/// and by anyone reconstructing the statement a block proof must verify against.
/// Both sides derive the header from the same function, so neither can drift on
/// where the header ends and the transfer limbs begin — the settlement contract
/// performs this same derivation on the verified statement bytes.
///
/// # Errors
///
/// Returns a message if any count exceeds what a `u16` limb can hold.
pub fn shape_header<'a>(
    shapes: impl IntoIterator<Item = &'a TransferShape>,
) -> Result<Vec<u16>, String> {
    let shapes: Vec<&TransferShape> = shapes.into_iter().collect();
    let mut header = Vec::with_capacity(shape_header_len(shapes.len()));
    header
        .push(u16::try_from(shapes.len()).map_err(|_| "block has too many transfers".to_string())?);
    for shape in shapes {
        header.push(
            u16::try_from(shape.num_nullifiers)
                .map_err(|_| "transfer has too many inputs".to_string())?,
        );
        header.push(
            u16::try_from(shape.num_outputs)
                .map_err(|_| "transfer has too many outputs".to_string())?,
        );
    }
    Ok(header)
}

/// A client-produced transfer proof, presented for verification inside a block.
///
/// The verifier travels with the proof: transfers of different shapes (different
/// spend and output counts) are different circuits with different verifiers, and a
/// block may mix them.
pub struct ChildProof<'a> {
    /// The verifier retained from the client's own proving run.
    pub verifier: &'a p3_circuit_prover::CircuitVerifier<InnerWhirConfig>,
    /// The proof the client produced.
    pub proof: &'a p3_circuit_prover::BatchStarkProof<InnerWhirConfig>,
    /// The statement the client proved against.
    pub statement: &'a [F],
    /// The shape of [`Self::statement`], used to locate the shared root.
    pub shape: TransferShape,
}

// `CircuitVerifier` and `BatchStarkProof` do not implement `Debug`, and dumping a
// proof would be megabytes of noise. Report what identifies the child.
impl core::fmt::Debug for ChildProof<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChildProof")
            .field("statement_len", &self.statement.len())
            .finish_non_exhaustive()
    }
}

/// Verify every child transfer proof inside one circuit and export their
/// statements concatenated.
///
/// Each child is re-verified through the trusted entry point, so a child's
/// relation comes from its retained verifier rather than from anything the proof
/// asserts. The exported statement is the concatenation of the children's
/// statement values in order.
///
/// # Errors
///
/// Returns an error if `children` is empty, if a child verifier carries no
/// statement table, if a child proof fails native verification, or if the
/// circuit cannot be witnessed.
pub fn build_multi_transfer_circuit(
    inner: &InnerWhirConfig,
    children: &[ChildProof<'_>],
) -> Result<RecursionCircuit, Box<dyn Error>> {
    if children.is_empty() {
        return Err("a block must verify at least one transfer proof".into());
    }

    let perm = Poseidon2Config::KOALA_BEAR_D4_W16;
    let backend = WhirRecursionBackend::<16, 8>::new(perm).for_extension_degree::<4>();

    let mut builder = CircuitBuilder::new();
    PcsRecursionBackend::<InnerWhirConfig, BatchOnly, 4>::prepare_circuit(
        &backend,
        inner,
        &mut builder,
    )?;

    let mut exports: Vec<StatementExport> = Vec::new();
    let mut public: Vec<Challenge> = Vec::new();
    let mut private: Vec<Challenge> = Vec::new();
    // Each child carries its own private-data replay, keyed on the op ids its own
    // verification allocated. They cannot be merged: the replay drives one
    // child's transcript.
    let mut replays: Vec<Replay<'_>> = Vec::new();
    // The first child's root limbs, against which every later child's root is
    // constrained. See "Shared anchor" in the module docs.
    let mut anchor = RootAnchor::default();
    // The nullifier-map root chain across children. See "Nullifier roots are
    // chained, not pinned" in the module docs.
    let mut nullifiers = NullifierChain::default();

    // Shape header, exported as circuit constants so the split is bound by the
    // proof rather than asserted by the caller. Without this the settlement
    // contract would have to be *told* how many nullifiers each transfer has,
    // and a prover could declare a split that makes the contract read an output
    // commitment as a nullifier — or skip a real nullifier entirely.
    //
    // The counts are the ones the prover actually verified against: they come
    // from each child's shape, which was checked against that child's statement
    // length before its proof was verified. The contract re-derives the same
    // split from the statement's own length, so a header that disagrees with
    // the statement it ships with cannot be produced.
    let header = shape_header(children.iter().map(|child| &child.shape))?;
    // The header limbs are circuit *constants*, not public inputs: `define_const`
    // bakes each value into the const trace, so the statement value is proven
    // rather than supplied by the prover. They therefore must NOT be pushed into
    // the public-input vector — that vector's width is fixed by the public-input
    // slots the child verifications allocate.
    for value in header {
        let limb = Challenge::from_u16(value);
        exports.push(StatementExport::Base(builder.define_const(limb)));
    }
    debug_assert_eq!(exports.len(), shape_header_len(children.len()));

    for child in children {
        let expected = child.shape.statement_len();
        if child.statement.len() != expected {
            return Err(format!(
                "child statement has {} limbs, shape {:?} implies {expected}",
                child.statement.len(),
                child.shape,
            )
            .into());
        }

        let statement_instance = child
            .verifier
            .statement_layout()
            .table_instance()
            .ok_or("child verifier carries no statement table to bind")?;

        let (verifier_inputs, op_ids) = verify_trusted_p3_batch_proof_circuit::<
            InnerWhirConfig,
            MerkleCapTargets<F, DIGEST_ELEMS>,
            (),
            WhirUniProofTargets<F, Challenge, WhirMmcs, DIGEST_ELEMS>,
            LogUpGadget,
            Poseidon2Config,
            16,
            8,
            4,
        >(
            child.verifier,
            &mut builder,
            child.proof,
            child.statement,
            inner.pcs_verifier_params(),
            &LogUpGadget::new(),
            perm,
        )?;

        // Bind the statement: the exported base values are the AIR public
        // targets of this child's statement table instance — exactly the targets
        // the in-circuit verifier constrained against the child proof.
        let statement_targets = verifier_inputs
            .air_public_targets
            .get(statement_instance)
            .ok_or("statement table instance absent from verifier inputs")?;
        exports.extend(statement_targets.iter().copied().map(StatementExport::Base));

        // Pin this child's root to the block's shared root.
        anchor.pin(&mut builder, child.shape, statement_targets)?;
        // Chain this child's nullifier transition onto the previous one's.
        nullifiers.advance(&mut builder, child.shape, statement_targets)?;

        let table_public_inputs = child.verifier.table_public_values(child.statement)?;
        public.extend(verifier_inputs.try_pack_public_values(
            &table_public_inputs,
            &child.proof.proof,
            child.verifier.common_data(),
        )?);
        private.extend(verifier_inputs.try_pack_private_values(&child.proof.proof)?);

        replays.push(Replay {
            verifier: child.verifier,
            proof: child.proof,
            statement: child.statement,
            op_ids,
        });
    }

    let schema = builder.set_statement_exports::<F>(&exports)?;
    let circuit = builder.build()?;

    let mut runner = circuit.runner();
    runner.set_public_inputs(&public)?;
    runner.set_private_inputs(&private)?;
    for replay in &replays {
        TrustedPcsRecursionBackend::<InnerWhirConfig, BatchOnly, 4>::set_private_data_for_trusted_batch(
            &backend,
            replay.verifier,
            replay.proof,
            replay.statement,
            &mut runner,
            &replay.op_ids,
        )?;
    }
    let traces = runner.run()?;

    Ok(RecursionCircuit {
        circuit,
        traces,
        schema,
    })
}

/// Constrain two equal-length limb vectors to be elementwise equal.
///
/// Expressed arithmetically (`a - b = 0`) rather than with
/// `CircuitBuilder::connect`. `connect` aliases witness slots, and the statement
/// table's `LogUp` multiplicities are tracked per instance; aliasing across two
/// children's instances desynchronises them and the witness fails to balance.
/// A subtraction is a plain ALU constraint and leaves the lookup structure alone.
fn assert_limbs_equal(
    builder: &mut CircuitBuilder<Challenge>,
    anchor: &[ExprId; LIMBS_PER_HASH],
    limb: &[ExprId; LIMBS_PER_HASH],
) {
    for (a, b) in anchor.iter().zip(limb) {
        let diff = builder.sub(*a, *b);
        builder.assert_zero(diff);
    }
}

/// Read 16 statement limbs out of a child's target slice.
///
/// Bounds-checked: a shape pointing past the end of the statement is an error,
/// not a panic and not a silent short read.
fn take_limbs(
    targets: &[ExprId],
    offset: usize,
    what: &str,
) -> Result<[ExprId; LIMBS_PER_HASH], Box<dyn Error>> {
    let limbs: [ExprId; LIMBS_PER_HASH] = targets
        .get(offset..offset + LIMBS_PER_HASH)
        .ok_or("root limbs outside statement target range")?
        .try_into()
        .map_err(|_| format!("{what} limb count mismatch"))?;
    Ok(limbs)
}

/// The block's shared commitment-root invariant.
///
/// The first child observed defines the anchor; every later child is constrained
/// equal to it. Callers cannot inspect or bypass the pinned value — the only way
/// to use this is to feed it each child in turn, which is exactly the invariant
/// the block needs.
#[derive(Default)]
struct RootAnchor {
    pinned: Option<[ExprId; LIMBS_PER_HASH]>,
}

impl RootAnchor {
    /// Constrain `targets[shape.root_offset()..]` to the block's shared root,
    /// or adopt it as the anchor if this is the first child.
    fn pin(
        &mut self,
        builder: &mut CircuitBuilder<Challenge>,
        shape: TransferShape,
        targets: &[ExprId],
    ) -> Result<(), Box<dyn Error>> {
        let limbs = take_limbs(targets, shape.root_offset(), "root")?;
        match self.pinned {
            None => self.pinned = Some(limbs),
            Some(first) => assert_limbs_equal(builder, &first, &limbs),
        }
        Ok(())
    }
}

/// The block's nullifier-root chain.
///
/// Unlike the commitment root, the nullifier map genuinely changes inside every
/// transfer that spends, so the children cannot share one value. They are
/// chained instead: each child's `before` must equal the previous child's
/// `after`. The first child's `before` is the block's `root_before` and the
/// last child's `after` is its `root_after`.
///
/// The chain is what makes replay impossible without a contract-side nullifier
/// set (D-032): a transfer that reuses a nullifier cannot find an absent-fold
/// that lands on the root it inherited, so the block is simply unwitnessable.
#[derive(Default)]
struct NullifierChain {
    /// The previous child's `after`, which the next child's `before` must match.
    expected_before: Option<[ExprId; LIMBS_PER_HASH]>,
    /// The most recent `after`, i.e. the block's own `root_after`.
    latest_after: Option<[ExprId; LIMBS_PER_HASH]>,
}

impl NullifierChain {
    /// Check one child's `before` against the chain and advance it.
    fn advance(
        &mut self,
        builder: &mut CircuitBuilder<Challenge>,
        shape: TransferShape,
        targets: &[ExprId],
    ) -> Result<(), Box<dyn Error>> {
        let before = take_limbs(targets, shape.nullifier_before_offset(), "nullifier before")?;
        let after = take_limbs(targets, shape.nullifier_after_offset(), "nullifier after")?;
        if let Some(prev_after) = self.expected_before {
            assert_limbs_equal(builder, &prev_after, &before);
        }
        self.expected_before = Some(after);
        self.latest_after = Some(after);
        Ok(())
    }
}

/// One child's private-data replay parameters.
struct Replay<'a> {
    verifier: &'a p3_circuit_prover::CircuitVerifier<InnerWhirConfig>,
    proof: &'a p3_circuit_prover::BatchStarkProof<InnerWhirConfig>,
    statement: &'a [F],
    op_ids: Vec<NonPrimitiveOpId>,
}

/// Prove a block circuit under the Keccak settlement config, producing the proof
/// L1 verifies.
///
/// # Errors
///
/// Returns an error if the settlement config cannot be sized for this circuit.
pub fn settle_block_circuit(
    rc: &RecursionCircuit,
    log_max_lde: usize,
) -> Result<
    (
        p3_circuit_prover::BatchStarkProof<crate::whir::Config>,
        p3_circuit_prover::CircuitVerifier<crate::whir::Config>,
    ),
    Box<dyn Error>,
> {
    // Cap height is the number of top Merkle levels withheld from the
    // commitment and held by the verifier as public data. Every query's
    // authentication path is `depth - cap_height` long, so raising the cap
    // shortens the dominant term of the proof with no security loss: the cap
    // is a handful of digests the verifier holds once.
    //
    // Measured at cap 0 the final proof is 767 KB, dominated by 24-level
    // Keccak paths. See D-038.
    let settlement = crate::whir::config(BLOCK_CAP_HEIGHT, log_max_lde)?;
    let shared = Poseidon2Config::KOALA_BEAR_D4_W16.for_shared_challenger_table();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2SharedPreprocessor::new(vec![shared])),
        recompose_preprocessor::<F>(true),
        Box::new(StatementPreprocessor::new(rc.schema.clone())),
    ];
    let mut air_builders: Vec<Box<dyn NpoAirBuilder<crate::whir::Config, 4>>> =
        poseidon2_air_builders_for_configs::<crate::whir::Config, 4>(vec![shared]);
    air_builders.push(Box::new(RecomposeAirBuilder::<4>::new(1, true)));
    air_builders.push(Box::new(StatementAirBuilder::<4>::new(rc.schema.clone())));

    let mut prover = BatchStarkProver::new(settlement)
        .with_table_packing(ProveNextLayerParams::default().table_packing);
    prover.register_poseidon2_table::<4>(shared);
    prover.register_recompose_table::<4>(true);
    prover.register_table_prover(Box::new(StatementProver::<4>::new(rc.schema.clone())));
    let prepared = prover.prepare_circuit(
        &rc.circuit,
        &preprocessors,
        &air_builders,
        ConstraintProfile::Standard,
    )?;
    let proof = prepared.prove(&rc.traces)?;
    Ok((proof, prepared.verifier()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{funded_note, nullifier_transition, seed, tree_with};
    use crate::transfer::{build_transfer_circuit, settle_transfer_circuit_with, LOG_MAX_LDE};
    use p3_field::PrimeCharacteristicRing;
    use pq_hash::{Keccak256Commitment, Sha3_256Shielded};
    use shielded::keys::derive_spend_pk;
    use shielded::transfer::Spend;
    use shielded::{Note, NullifierMap};

    /// Every transfer in these tests spends one note and creates one.
    const ONE_IN_ONE_OUT: TransferShape = TransferShape {
        num_nullifiers: 1,
        num_outputs: 1,
    };

    /// What a block needs from one client's proving run.
    type ClientTransfer = (
        p3_circuit_prover::CircuitVerifier<InnerWhirConfig>,
        p3_circuit_prover::BatchStarkProof<InnerWhirConfig>,
        Vec<F>,
    );

    /// The nullifier map the block's clients share.
    ///
    /// One map across the whole block, not one per client: the chain constraint
    /// only means something if the children are transitions of the *same* map.
    type NullifierStore = NullifierMap<Keccak256Commitment>;

    /// One client's transfer witness, as it would exist on the spender's machine.
    struct ClientSpec<'a> {
        note: &'a Note,
        sk_d: &'a [u8; 32],
        path: &'a [pq_hash::Digest32],
        index: usize,
        out_value: u64,
    }

    /// Build and prove one client transfer, as a spender would on their own
    /// machine, returning the artefacts a block consumes.
    fn prove_client_transfer(
        inner: &InnerWhirConfig,
        spec: &ClientSpec<'_>,
        root: pq_hash::MerkleRoot,
        recipient: shielded::SpendPublicKey,
        map: &mut NullifierStore,
    ) -> Result<ClientTransfer, Box<dyn Error>> {
        let out = Note::new(spec.out_value, seed(200), seed(201), recipient);
        let spend = Spend {
            note: spec.note,
            sk_d: spec.sk_d,
            path: spec.path,
            index: spec.index,
        };
        let transfer = Transfer {
            spends: vec![spend],
            outputs: vec![out],
            fee: 100,
        };
        // The roots and the witnesses come out of one walk of the shared map, so
        // this client's `before` is whatever the previous client left behind.
        let (nullifier_roots, witnesses) = nullifier_transition(&transfer, map);
        let public = transfer.public(
            &Keccak256Commitment,
            &Sha3_256Shielded,
            root,
            nullifier_roots,
        );
        let tc = build_transfer_circuit(&transfer, &public, &witnesses)?;
        let (proof, verifier) = settle_transfer_circuit_with(&tc, inner.clone())?;
        verifier.verify(&proof, tc.statement())?;
        Ok((verifier, proof, tc.statement().to_vec()))
    }

    /// The shared-root anchor must reject a block assembled from transfers
    /// witnessed against **different** tree states.
    ///
    /// Each transfer is individually valid against its own root, so without the
    /// anchor the concatenated statement would attest to a state transition of
    /// a tree that never existed. This is the soundness property the anchor
    /// exists for, so it is tested directly.
    #[test]
    fn block_rejects_children_from_different_tree_states() -> Result<(), Box<dyn Error>> {
        let (n1, sk1) = funded_note(11, 1_000);
        let (n2, sk2) = funded_note(22, 2_000);
        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));
        let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0).expect("inner config");

        // Two *separate* trees, so the two transfers carry different roots.
        let (tree_a, paths_a) = tree_with(&[n1]);
        let (tree_b, paths_b) = tree_with(&[n2]);
        assert_ne!(
            tree_a.root(),
            tree_b.root(),
            "the test needs two distinct roots to be meaningful"
        );

        let spec_a = ClientSpec {
            note: &n1,
            sk_d: &sk1,
            path: &paths_a[0],
            index: 0,
            out_value: 900,
        };
        let spec_b = ClientSpec {
            note: &n2,
            sk_d: &sk2,
            path: &paths_b[0],
            index: 0,
            out_value: 1_900,
        };
        let mut map = NullifierMap::new(Keccak256Commitment);
        let client_a = prove_client_transfer(&inner, &spec_a, tree_a.root(), recipient, &mut map)?;
        let client_b = prove_client_transfer(&inner, &spec_b, tree_b.root(), recipient, &mut map)?;

        let children = children_of(std::iter::once(&client_a).chain(std::iter::once(&client_b)));

        let err = build_multi_transfer_circuit(&inner, &children)
            .expect_err("mixed tree states must not be provable");
        // The anchor is a circuit constraint, so it surfaces when the circuit is
        // witnessed — an unsatisfiable witness set is reported as a witness
        // conflict, not as a build-time configuration error. Verified by A/B:
        // with the anchor removed this same input builds and proves cleanly.
        let msg = err.to_string();
        assert!(
            msg.contains("conflict"),
            "mixed-root block must fail as an unsatisfiable constraint, got: {msg}"
        );

        Ok(())
    }

    /// The nullifier chain must reject a block whose children are transitions of
    /// **different** nullifier maps.
    ///
    /// This is the mirror of [`block_rejects_children_from_different_tree_states`],
    /// and it isolates a different property: there, the commitment roots differ.
    /// Here the commitment root is shared and every transfer is individually
    /// valid, but the second child starts from a nullifier root the first child
    /// did not produce.
    ///
    /// That is exactly what a replay looks like. A spender who reuses a
    /// nullifier cannot extend the chain — the absent-fold inside their proof
    /// cannot land on the root they inherited — so the block is unwitnessable
    /// without the contract ever holding a nullifier set (D-032).
    #[test]
    fn block_rejects_a_broken_nullifier_chain() -> Result<(), Box<dyn Error>> {
        let (n1, sk1) = funded_note(11, 1_000);
        let (n2, sk2) = funded_note(22, 2_000);
        let (tree, paths) = tree_with(&[n1, n2]);
        let root = tree.root();
        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));
        let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0).expect("inner config");

        let spec_a = ClientSpec {
            note: &n1,
            sk_d: &sk1,
            path: &paths[0],
            index: 0,
            out_value: 900,
        };
        let spec_b = ClientSpec {
            note: &n2,
            sk_d: &sk2,
            path: &paths[1],
            index: 1,
            out_value: 1_900,
        };

        // Same tree, but client B was witnessed against its own fresh map, so
        // its `before` is the empty-map root rather than client A's `after`.
        let mut map_a = NullifierMap::new(Keccak256Commitment);
        let mut map_b = NullifierMap::new(Keccak256Commitment);
        let client_a = prove_client_transfer(&inner, &spec_a, root, recipient, &mut map_a)?;
        let client_b = prove_client_transfer(&inner, &spec_b, root, recipient, &mut map_b)?;
        assert_ne!(
            map_a.root(),
            map_b.root(),
            "the two maps must actually differ for this test to mean anything"
        );

        let children = children_of(std::iter::once(&client_a).chain(std::iter::once(&client_b)));
        let err = build_multi_transfer_circuit(&inner, &children)
            .expect_err("a broken nullifier chain must not be provable");
        let msg = err.to_string();
        assert!(
            msg.contains("conflict"),
            "a broken nullifier chain must fail as an unsatisfiable constraint, got: {msg}"
        );

        Ok(())
    }

    /// Wrap proven clients as block children, all of [`ONE_IN_ONE_OUT`] shape.
    fn children_of<'a>(clients: impl Iterator<Item = &'a ClientTransfer>) -> Vec<ChildProof<'a>> {
        clients
            .map(|c| ChildProof {
                verifier: &c.0,
                proof: &c.1,
                statement: &c.2,
                shape: ONE_IN_ONE_OUT,
            })
            .collect()
    }

    /// A declared shape that does not match the statement is rejected up front,
    /// before any constraint is emitted. A wrong shape would otherwise pin the
    /// anchor to the wrong limbs.
    #[test]
    fn block_rejects_shape_statement_mismatch() -> Result<(), Box<dyn Error>> {
        let (n1, sk1) = funded_note(11, 1_000);
        let (n2, sk2) = funded_note(22, 2_000);
        let (tree, paths) = tree_with(&[n1, n2]);
        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));
        let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0).expect("inner config");

        let spec_a = ClientSpec {
            note: &n1,
            sk_d: &sk1,
            path: &paths[0],
            index: 0,
            out_value: 900,
        };
        let spec_b = ClientSpec {
            note: &n2,
            sk_d: &sk2,
            path: &paths[1],
            index: 1,
            out_value: 1_900,
        };
        let mut map = NullifierMap::new(Keccak256Commitment);
        let client_a = prove_client_transfer(&inner, &spec_a, tree.root(), recipient, &mut map)?;
        let client_b = prove_client_transfer(&inner, &spec_b, tree.root(), recipient, &mut map)?;

        // Same valid children, but the second claims two outputs.
        let mut children = children_of(std::iter::once(&client_a));
        children.push(ChildProof {
            verifier: &client_b.0,
            proof: &client_b.1,
            statement: &client_b.2,
            shape: TransferShape {
                num_nullifiers: 1,
                num_outputs: 2,
            },
        });

        let err = build_multi_transfer_circuit(&inner, &children)
            .expect_err("a lying shape must be rejected");
        assert!(
            err.to_string().contains("shape"),
            "error should name the shape mismatch, got: {err}"
        );

        Ok(())
    }

    /// Reconstruct the statement a block proof must verify against: the shape
    /// header, then each child's statement in order. Derived through the same
    /// [`shape_header`] the circuit exported, so neither side can drift.
    fn block_statement(
        shapes: [TransferShape; 2],
        children: [&[F]; 2],
    ) -> Result<Vec<F>, Box<dyn Error>> {
        let mut expected: Vec<F> = shape_header(shapes.iter())?
            .iter()
            .map(|&v| F::from_u16(v))
            .collect();
        for child in children {
            expected.extend_from_slice(child);
        }
        Ok(expected)
    }

    /// A block that verifies two independently-produced client transfer proofs.
    ///
    /// This is the shape the whole design turns on: the recursive prover verifies
    /// *client* proofs. Each transfer is built and proven as a client would build
    /// and prove it - its own circuit, its own `sk_d`, its own statement - and
    /// the block circuit only ever sees proofs and public statements.
    ///
    /// ```text
    ///   transfer A --prove--> proof A (Poseidon2 WHIR) --+
    ///                                                   +-- block circuit --> Keccak WHIR
    ///   transfer B --prove--> proof B (Poseidon2 WHIR) --+
    /// ```
    ///
    /// Asserts the block statement is the shape header followed by both
    /// transfers' statements, and that tampering with either end is rejected.
    #[test]
    fn block_verifies_two_client_transfer_proofs() -> Result<(), Box<dyn Error>> {
        let (n1, sk1) = funded_note(11, 1_000);
        let (n2, sk2) = funded_note(22, 2_000);
        let (tree, paths) = tree_with(&[n1, n2]);
        let root = tree.root();
        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));

        let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0).expect("inner config");

        // Two clients, each proving their own transfer locally.
        let spec_a = ClientSpec {
            note: &n1,
            sk_d: &sk1,
            path: &paths[0],
            index: 0,
            out_value: 900,
        };
        let spec_b = ClientSpec {
            note: &n2,
            sk_d: &sk2,
            path: &paths[1],
            index: 1,
            out_value: 1_900,
        };
        let mut map = NullifierMap::new(Keccak256Commitment);
        let client_a = prove_client_transfer(&inner, &spec_a, root, recipient, &mut map)?;
        let client_b = prove_client_transfer(&inner, &spec_b, root, recipient, &mut map)?;

        let children = vec![
            ChildProof {
                verifier: &client_a.0,
                proof: &client_a.1,
                statement: &client_a.2,
                shape: ONE_IN_ONE_OUT,
            },
            ChildProof {
                verifier: &client_b.0,
                proof: &client_b.1,
                statement: &client_b.2,
                shape: ONE_IN_ONE_OUT,
            },
        ];

        let rc = build_multi_transfer_circuit(&inner, &children)?;
        let (block_proof, block_verifier) = settle_block_circuit(&rc, BLOCK_LOG_MAX_LDE)?;

        // The block statement is the shape header, then both transfers'
        // statements in order. Rebuilt through the same `shape_header` the
        // circuit used, so the two cannot drift on where the header ends.
        let expected =
            block_statement([ONE_IN_ONE_OUT, ONE_IN_ONE_OUT], [&client_a.2, &client_b.2])?;
        block_verifier.verify(&block_proof, &expected)?;

        // Tampering with either half must be rejected.
        let mut tampered = expected.clone();
        tampered[0] += F::ONE;
        assert!(
            block_verifier.verify(&block_proof, &tampered).is_err(),
            "tampering the first transfer's nullifier must be rejected"
        );
        // `expected` is moved here rather than cloned: it is not read again.
        let mut tampered = expected;
        let last = tampered.len() - 1;
        tampered[last] += F::ONE;
        assert!(
            block_verifier.verify(&block_proof, &tampered).is_err(),
            "tampering the second transfer's fee must be rejected"
        );

        Ok(())
    }

    /// The size of the proof that actually reaches the chain.
    ///
    /// This is the number that decides whether on-chain verification is
    /// feasible: the serialized block proof IS the calldata, and calldata is
    /// 16 gas per non-zero byte on Cancun. A 40 KB proof is ~640k gas of
    /// calldata alone before a single WHIR round is verified.
    ///
    /// Reported alongside the statement length, because both travel in the
    /// calldata, and alongside the per-round query counts, because those drive
    /// the compute side of the cost.
    #[test]
    #[ignore = "size probe; run with --nocapture when sizing the settlement calldata"]
    fn measure_final_proof_size() -> Result<(), Box<dyn Error>> {
        let (n1, sk1) = funded_note(11, 1_000);
        let (n2, sk2) = funded_note(22, 2_000);
        let (tree, paths) = tree_with(&[n1, n2]);
        let root = tree.root();
        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));
        let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0).expect("inner config");

        let spec_a = ClientSpec {
            note: &n1,
            sk_d: &sk1,
            path: &paths[0],
            index: 0,
            out_value: 900,
        };
        let spec_b = ClientSpec {
            note: &n2,
            sk_d: &sk2,
            path: &paths[1],
            index: 1,
            out_value: 1_900,
        };
        let mut map = NullifierMap::new(Keccak256Commitment);
        let client_a = prove_client_transfer(&inner, &spec_a, root, recipient, &mut map)?;
        let client_b = prove_client_transfer(&inner, &spec_b, root, recipient, &mut map)?;
        let children = children_of(std::iter::once(&client_a).chain(std::iter::once(&client_b)));

        let rc = build_multi_transfer_circuit(&inner, &children)?;
        let (block_proof, _v) = settle_block_circuit(&rc, BLOCK_LOG_MAX_LDE)?;

        let bytes = postcard::to_allocvec(&block_proof).expect("serialize");

        // Decompose: what dominates the proof? Serialize each piece on its own
        // rather than guessing at field sizes — the answer decides where to
        // optimize, so it must be measured, not estimated.
        let op = &block_proof.proof.opening_proof;
        println!(
            "opening_proof total: {}",
            postcard::to_allocvec(op).map_or(0, |b| b.len())
        );
        for (i, rp) in op.rounds.iter().enumerate() {
            println!(
                "  round {i}: {} bytes ({} whir rounds, {} evals)",
                postcard::to_allocvec(rp).map_or(0, |b| b.len()),
                rp.whir.rounds.len(),
                rp.evals.len(),
            );
            for (j, wr) in rp.whir.rounds.iter().enumerate() {
                println!(
                    "    whir round {j}: {} bytes, ood={} sumcheck={}",
                    postcard::to_allocvec(wr).map_or(0, |b| b.len()),
                    wr.ood_answers.len(),
                    wr.sumcheck.polynomial_evaluations.len(),
                );
            }
        }
        let statement =
            block_statement([ONE_IN_ONE_OUT, ONE_IN_ONE_OUT], [&client_a.2, &client_b.2])?;
        // Each statement limb is a base-field element serialized as one
        // little-endian u32, so the statement's wire size is 4 bytes per limb.
        let stmt_bytes = statement.len() * 4;

        // Calldata gas on Cancun: 16 per non-zero byte, 4 per zero byte.
        let nonzero = bytes.iter().filter(|&&b| b != 0).count();
        let zeros = bytes.len() - nonzero;
        let calldata_gas = nonzero * 16 + zeros * 4;

        println!(
            "FINAL PROOF: {} bytes ({} nonzero, {} zero) | statement {} limbs / {} bytes\n\
             calldata gas ~{} (16/byte nonzero, 4/byte zero)\n\
             inner transfer proofs: {} and {} bytes",
            bytes.len(),
            nonzero,
            zeros,
            statement.len(),
            stmt_bytes,
            calldata_gas,
            postcard::to_allocvec(&client_a.1).map_or(0, |b| b.len()),
            postcard::to_allocvec(&client_b.1).map_or(0, |b| b.len()),
        );
        Ok(())
    }

    /// How the final proof size scales with block fan-in.
    ///
    /// This is the question that decides whether the rollup is economical, and
    /// the answer is not obvious from a single measurement. The final proof is
    /// the WHIR proof of the RECURSION circuit, whose trace is dominated by
    /// the fixed cost of verifying inner proofs (Poseidon2 rounds, statement
    /// tables, ALU rows) — not by the shielded logic of each transfer.
    ///
    /// If size grows slowly with fan-in, the per-transfer cost collapses:
    /// 767 KB over 2 transfers is ruinous, the same over 32 is 24 KB each.
    /// The curve below is the economic basis for choosing the aggregation
    /// fan-in (D-028).
    #[test]
    #[ignore = "scaling probe; run with --nocapture when choosing the aggregation fan-in"]
    fn measure_proof_size_vs_fan_in() -> Result<(), Box<dyn Error>> {
        let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));
        let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0).expect("inner config");

        println!("fan_in | block_bytes | bytes_per_transfer | total_queries");
        println!("-------+-------------+--------------------+--------------");
        for fan in [1usize, 2, 4, 8] {
            let mut map = NullifierMap::new(Keccak256Commitment);
            let mut clients = Vec::new();
            let mut notes = Vec::new();
            for i in 0..fan {
                notes.push(funded_note(u8::try_from(i + 1).expect("small"), 1_000));
            }
            let plain: Vec<Note> = notes.iter().map(|(n, _)| *n).collect();
            let (tree, paths) = tree_with(&plain);
            let root = tree.root();
            for (i, (note, sk)) in notes.iter().enumerate() {
                let spec = ClientSpec {
                    note,
                    sk_d: sk,
                    path: &paths[i],
                    index: i,
                    out_value: 900,
                };
                clients.push(prove_client_transfer(
                    &inner, &spec, root, recipient, &mut map,
                )?);
            }
            let children = children_of(clients.iter());
            let rc = build_multi_transfer_circuit(&inner, &children)?;
            // Fan-in changes the stacked arity, so the height budget must grow
            // with it. Search upward for the smallest that builds: the WHIR
            // budget panics when under-provisioned, so try each level and keep
            // the first that works.
            // `WhirConfig::new` PANICS (does not return Err) when the grinding
            // budget is below what the committed arity requires, so the search
            // for the smallest feasible height has to catch the panic rather
            // than match on a Result.
            let mut reported = false;
            for lde in 24..=28 {
                let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    settle_block_circuit(&rc, lde)
                }));
                if let Ok(Ok((block_proof, _v))) = attempt {
                    let bytes = postcard::to_allocvec(&block_proof).map_or(0, |b| b.len());
                    println!("{fan:>6} | {:>11} | {:>18} | lde {lde}", bytes, bytes / fan);
                    reported = true;
                    break;
                }
            }
            assert!(reported, "no height budget built for fan-in {fan}");
        }
        Ok(())
    }

    use shielded::Transfer;
}
