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
//! ## What is *not* checked here
//!
//! Nullifier uniqueness is deliberately absent. The settlement contract inserts
//! every nullifier into an on-chain set and reverts on a duplicate, covering
//! within-block and cross-block replay with one mechanism the chain owns
//! authoritatively. Re-deriving it in-circuit would add a quadratic comparison
//! to duplicate a check that is already enforced where the state lives.

use crate::whir_recursion::{Challenge, InnerWhirConfig, RecursionCircuit, WhirMmcs, DIGEST_ELEMS};
use p3_circuit::{CircuitBuilder, NonPrimitiveOpId, StatementExport};
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

    for child in children {
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
        let mut clients = Vec::new();
        for (note, sk, path, index, out_value) in [
            (&n1, &sk1, &paths[0], 0usize, 900u64),
            (&n2, &sk2, &paths[1], 1usize, 1_900u64),
        ] {
            let out = Note::new(out_value, seed(200), seed(201), recipient);
            let spend = Spend {
                note,
                sk_d: sk,
                path,
                index,
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
            clients.push((verifier, proof, tc.statement().to_vec()));
        }

        let children: Vec<ChildProof<'_>> = clients
            .iter()
            .map(|(verifier, proof, statement)| ChildProof {
                verifier,
                proof,
                statement,
            })
            .collect();

        let rc = build_multi_transfer_circuit(&inner, &children)?;
        let (block_proof, block_verifier) = settle_block_circuit(&rc, BLOCK_LOG_MAX_LDE)?;

        // The block statement is both transfers' statements, in order.
        let mut expected: Vec<F> = Vec::new();
        expected.extend_from_slice(&clients[0].2);
        expected.extend_from_slice(&clients[1].2);
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
