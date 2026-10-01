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
//! The exported statement is the children's statement values concatenated in
//! order: `[transfer 0: nullifiers…, outputs…, root, fee, transfer 1: …]`.
//! That is what the settlement layer and L1 read to apply the state update.
//!
//! ## Shared anchor
//!
//! Every child is constrained to prove against the **same** root. Concatenating
//! statements without that link would let a prover assemble a block from
//! transfers witnessed against *different* tree states — each child individually
//! valid, the set collectively describing a tree that never existed. The anchor
//! equality is what makes the concatenated statement describe one real state
//! transition, so it is enforced here, not left to the settlement layer.
//!
//! ## What is *not* checked here
//!
//! Nullifier uniqueness is deliberately absent. The settlement contract inserts
//! every nullifier into an on-chain set and reverts on a duplicate, covering
//! within-block and cross-block replay with one mechanism the chain owns
//! authoritatively. Re-deriving it in-circuit would add a quadratic comparison
//! to duplicate a check that is already enforced where the state lives.

use crate::whir_recursion::{Challenge, InnerWhirConfig, RecursionCircuit, WhirMmcs, DIGEST_ELEMS};
use p3_circuit::{CircuitBuilder, ExprId, NonPrimitiveOpId, StatementExport};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    poseidon2_air_builders_for_configs, recompose_preprocessor, BatchStarkProver,
    ConstraintProfile, Poseidon2SharedPreprocessor, RecomposeAirBuilder, StatementAirBuilder,
    StatementPreprocessor, StatementProver,
};
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

/// Limbs per 32-byte hash in a transfer statement (32 bytes / 16-bit limbs).
const LIMBS_PER_HASH: usize = 16;
/// Limbs of the fee field in a transfer statement (`VALUE_LIMBS` in the
/// transfer circuit).
const FEE_LIMBS: usize = 4;

/// The shape of a transfer statement, needed to locate fields inside it.
///
/// A transfer exports, in this order:
/// `[nullifier_0…, output_0…, root, fee]` — 16 limbs per hash, 4 for the fee.
/// The block circuit needs this to find each child's `root` without guessing, so
/// a shape that does not match the statement it describes is rejected rather
/// than silently constraining the wrong limbs.
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
        LIMBS_PER_HASH * (self.num_nullifiers + self.num_outputs + 1) + FEE_LIMBS
    }

    /// Offset of the 16 root limbs within the statement.
    #[must_use]
    pub const fn root_offset(&self) -> usize {
        LIMBS_PER_HASH * (self.num_nullifiers + self.num_outputs)
    }
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

/// The block's shared-root invariant.
///
/// The first child observed defines the anchor; every later child is constrained
/// equal to it. Callers cannot inspect or bypass the pinned value — the only way
/// to use this is to feed it each child in turn, which is exactly the invariant
/// the block needs.
///
/// Equality is expressed arithmetically (`a - b = 0`) rather than with
/// `CircuitBuilder::connect`. `connect` aliases witness slots, and the statement
/// table's `LogUp` multiplicities are tracked per instance; aliasing across two
/// children's instances desynchronises them and the witness fails to balance.
/// A subtraction is a plain ALU constraint and leaves the lookup structure alone.
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
        let off = shape.root_offset();
        let limbs: [ExprId; LIMBS_PER_HASH] = targets
            .get(off..off + LIMBS_PER_HASH)
            .ok_or("root limbs outside statement target range")?
            .try_into()
            .map_err(|_| "root limb count mismatch")?;
        match self.pinned {
            None => self.pinned = Some(limbs),
            Some(first) => {
                for (anchor, limb) in first.iter().zip(limbs) {
                    let diff = builder.sub(*anchor, limb);
                    builder.assert_zero(diff);
                }
            }
        }
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
    let settlement = crate::whir::config(0, log_max_lde)?;
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
    use crate::fixtures::{funded_note, seed, tree_with};
    use crate::transfer::{build_transfer_circuit, settle_transfer_circuit_with, LOG_MAX_LDE};
    use p3_field::PrimeCharacteristicRing;
    use pq_hash::{Keccak256Commitment, Sha3_256Shielded};
    use shielded::keys::derive_spend_pk;
    use shielded::transfer::Spend;
    use shielded::Note;

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
        let public = transfer.public(&Keccak256Commitment, &Sha3_256Shielded, root);
        let tc = build_transfer_circuit(&transfer, &public)?;
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
        let client_a = prove_client_transfer(&inner, &spec_a, tree_a.root(), recipient)?;
        let client_b = prove_client_transfer(&inner, &spec_b, tree_b.root(), recipient)?;

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
        let client_a = prove_client_transfer(&inner, &spec_a, tree.root(), recipient)?;
        let client_b = prove_client_transfer(&inner, &spec_b, tree.root(), recipient)?;

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

    /// A block that verifies two independently-produced client transfer proofs.
    ///
    /// This is the shape the whole design turns on: the recursive prover verifies
    /// *client* proofs. Each transfer is built and proven as a client would build
    /// and prove it — its own circuit, its own `sk_d`, its own statement — and
    /// the block circuit only ever sees proofs and public statements.
    ///
    /// ```text
    ///   transfer A --prove--> proof A (Poseidon2 WHIR) ─┐
    ///                                                  ├─ block circuit ──▶ Keccak WHIR
    ///   transfer B --prove--> proof B (Poseidon2 WHIR) ─┘
    /// ```
    ///
    /// Asserts the block statement is both transfers' statements concatenated,
    /// and that tampering with either end of it is rejected.
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
        let client_a = prove_client_transfer(&inner, &spec_a, root, recipient)?;
        let client_b = prove_client_transfer(&inner, &spec_b, root, recipient)?;

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

        // The block statement is both transfers' statements, in order.
        let mut expected: Vec<F> = Vec::new();
        expected.extend_from_slice(&client_a.2);
        expected.extend_from_slice(&client_b.2);
        block_verifier.verify(&block_proof, &expected)?;

        // Tampering with either half must be rejected.
        let mut tampered = expected.clone();
        tampered[0] += F::ONE;
        assert!(
            block_verifier.verify(&block_proof, &tampered).is_err(),
            "tampering the first transfer's nullifier must be rejected"
        );
        let mut tampered = expected.clone();
        let last = tampered.len() - 1;
        tampered[last] += F::ONE;
        assert!(
            block_verifier.verify(&block_proof, &tampered).is_err(),
            "tampering the second transfer's fee must be rejected"
        );

        Ok(())
    }

    use shielded::Transfer;
}
