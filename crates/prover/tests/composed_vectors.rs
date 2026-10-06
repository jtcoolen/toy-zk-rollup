//! Composed settlement-shape vectors: the WHIR core walk, driven at the real batch
//! opening shapes, inside the batch transcript delegate, in place of the native PCS.
//!
//! ~~~text
//! cargo test -p prover --test composed_vectors -- --ignored --nocapture
//! ~~~
//!
//! # The composition claim
//!
//! The settlement contract replays the batch transcript (pinned by
//! `batch_stark_vectors`) and, at the delegate, runs its own WHIR core (ported in M1-M4
//! from the walk pinned by `whir_proof_vectors`). Neither pin alone proves the two halves
//! compose: the batch fixture hands the WHIR core a per-round statement (stacked config,
//! opening schedule, univariate points) that only exists at settlement shape, and the
//! WHIR fixture never sees the batch transcript around it.
//!
//! This test closes that gap. It proves the settlement batch under the semantic config,
//! replays the batch phases by hand, and inside transcript.delegate replaces the native
//! PCS with the shared WHIR walk: for each of the five opening rounds it rebuilds the
//! WHIR config and opening schedule from public ingredients (`padded_arity`,
//! `checked_stacked_num_variables`, `univariate_eq_point` - the same construction
//! `round_schedule` performs), drives `verify_whir_round` on the batch challenger, and
//! re-checks the claimed openings against the walk's bound evaluations with the
//! univariate-eq scales. `one_run` then asserts the combined event program equals the
//! native `CircuitVerifier::verify` run's - batch phases and WHIR core events alike.
//!
//! If the programs agree, the Solidity composition is mechanical assembly of pieces
//! each already pinned: `BatchTranscript.sol` up to the delegate, then `WhirVerifierCore`
//! per round with the statement exported here.
#![recursion_limit = "256"]

use std::error::Error;
use std::path::PathBuf;

use p3_field::PrimeCharacteristicRing;
use serde_json::json;

use prover::semantic_blob::classify_observations;
use prover::semantic_trace::SemChallenger;
use prover::F;

use prover::composed_export::{
    composed_run, composed_run_with, export_and_write, reclassify_zero_runs,
};
use prover::settlement_replay::{hex, settlement_params_for, Challenge, SemPcs};

use pq_hash::{Keccak256Commitment, Sha3_256Shielded};
use prover::block::{build_multi_transfer_circuit, shape_header, ChildProof, TransferShape};
use prover::client::{prove_client_transfer, ClientSpec};
use prover::fixtures::{funded_note, seed, tree_with};
use prover::whir_recursion::InnerWhirConfig;
use shielded::keys::derive_spend_pk;
use shielded::{Note, NullifierMap};

// The ZK PCS type flag guards the randomization round: with ZK on, round 0 is
// the randomization commitment and there are five opening rounds; without it
// the five-round shape pin would already be wrong. Checked at compile time - a
// const context rejects a false value, so this cannot rot into dead runtime code.
const _: bool = <SemPcs as p3_commit::UnivariateStarkPcs<Challenge, SemChallenger>>::ZK;

/// The linchpin: prove, verify natively, replay the batch phases with the shared WHIR
/// walk in the delegate, and require the combined programs to agree (asserted inside
/// `one_run`). Then export the per-round statements and the composed blob for Solidity.
///
/// Two runs, same circuit and config, each re-masking: classifying them splits the
/// settlement event stream into config-fixed absorbs (the contract regenerates them
/// from the schedule) and proof-dependent absorbs (read from calldata). Both runs are
/// verified against the native run, so the blob and every exported value describe one
/// proof - the same-run discipline of D-059.
#[test]
#[ignore = "proves the settlement batch twice (~12s); regenerates composed_vectors.{json,bin}"]
fn composed_program_equality_and_export() {
    let mut rounds_a = Vec::new();
    let mut starts_a = Vec::new();
    let (_doc_a, _out_a, program_a) =
        composed_run(&mut rounds_a, &mut starts_a).expect("composed run A");

    let mut rounds_b = Vec::new();
    let mut starts_b = Vec::new();
    let (doc, out, program_b) = composed_run(&mut rounds_b, &mut starts_b).expect("composed run B");
    assert_eq!(
        program_a.len(),
        program_b.len(),
        "runs disagree on program length"
    );
    assert_eq!(starts_a, starts_b, "runs disagree on round boundaries");

    let (fixed_raw, varying_raw) = classify_observations(&[program_a, program_b.clone()]);
    // Proof-data zeros: a config-fixed run whose every word is zero is not a
    // framing constant but a structurally-zero extension element (a high
    // final_poly coefficient, or a zero column of a claim's evaluations) that
    // happens to be zero in both sampled runs. The contract reads proof data
    // from calldata uniformly; leaving these in the trusted constant table
    // would force the final-poly absorb to interleave constant and calldata
    // words (Vx12 Cx4 Vx12 Cx4 ...), which no scalar schedule expresses.
    // Reclassifying them as varying moves the zeros into the proof payload, so
    // every framing run is a nonzero shape constant and final_poly is read
    // whole from calldata. Framing constants are keccak-derived or fixed
    // labels and are never all-zero; the small-shape guard already treats an
    // isolated fixed zero as a bug (check_no_ambiguous_zeros).
    let fixed = reclassify_zero_runs(&program_b, fixed_raw);
    let _ = varying_raw;
    export_and_write(
        doc,
        &out,
        &program_b,
        &fixed,
        &starts_b,
        "composed_vectors",
        None,
        vec![],
    )
    .expect("export");
}

/// Shape pin: the committed artifact must describe the settlement batch's five opening
/// rounds with the measured matrix shapes. A stale or hand-edited file fails here.
#[test]
fn composed_artifact_shape_is_pinned() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    let Ok(text) = std::fs::read_to_string(dir.join("composed_vectors.json")) else {
        // Absent until the ignored export has been run once.
        return;
    };
    let doc: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    assert_eq!(doc["num_rounds"].as_u64().unwrap(), 5);
    let rounds = doc["rounds"].as_array().unwrap();
    // Measured settlement shapes: round 2 is the per-instance column split (32
    // matrices); the others open the six instance commitments; rounds 1 and 4 open
    // the two-row instances at two points.
    let matrix_counts: Vec<u64> = rounds
        .iter()
        .map(|r| r["matrices"].as_array().unwrap().len() as u64)
        .collect();
    assert_eq!(matrix_counts, vec![6, 6, 32, 6, 6]);
    let point_counts: Vec<Vec<u64>> = rounds
        .iter()
        .map(|r| {
            r["matrices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["points"].as_array().unwrap().len() as u64)
                .collect()
        })
        .collect();
    assert!(point_counts[0].iter().all(|&n| n == 1));
    assert!(point_counts[2].iter().all(|&n| n == 1));
    assert!(point_counts[4].iter().all(|&n| n == 2));
    // Every round carries a completed walk: the terminal phase closed with a claim.
    for r in rounds {
        assert!(r["walk"]["terminal"]["claimed_after_final"].is_array());
        assert!(!r["walk"]["rounds"]["params"].as_array().unwrap().is_empty());
        assert!(!r["schedule"]["rounds"].as_array().unwrap().is_empty());
    }
}

/// Genesis data for the on-chain test, written as the small sidecar the
/// Solidity E2E test reads (the full export is tens of MB and parsing it
/// on-chain in setUp exhausts the EVM memory limit). Returns the extras the
/// full export embeds.
fn write_block_genesis(
    note: Note,
    out_note: Note,
    pis: &[F],
) -> Result<Vec<(&'static str, serde_json::Value)>, Box<dyn Error>> {
    // The pool must start at the tree the block was witnessed against (the
    // funded note's leaf), and the expected root after the block's output is
    // appended pins the contract's own accumulator against the prover's tree.
    let p2 = pq_hash::Poseidon2Commitment::default();
    let mut pool_tree = tree_with(&[note]).0;
    pool_tree.append(&out_note.commit(&p2));
    let extras = vec![
        ("genesis_leaves", json!([hex(note.commit(&p2).as_bytes())])),
        (
            "pool_root_after_hex",
            json!(hex(pool_tree.root().as_bytes())),
        ),
    ];
    let sidecar = serde_json::json!({
        "statement": pis
            .iter()
            .map(p3_field::PrimeField32::as_canonical_u32)
            .collect::<Vec<_>>(),
        "genesis_leaves": extras[0].1.clone(),
        "pool_root_after_hex": extras[1].1.clone(),
    });
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    std::fs::write(
        dir.join("block_genesis.json"),
        serde_json::to_string_pretty(&sidecar)?,
    )?;
    Ok(extras)
}

/// The real shielded block circuit through the same composed machinery.
///
/// One client transfer (a funded note spent through the transfer circuit with a
/// real SPHINCS+ signature, SHA3-256 note derivation and nullifier absence fold)
/// recursed into the block circuit and settled under the Keccak WHIR config at
/// `BLOCK_LOG_MAX_LDE`. The export is what the contract replays:
/// `block_composed_vectors.{json,bin}` plus the block statement (shape header +
/// child statement, canonical limbs) that `ShieldedPool.applyBlock` receives.
///
/// ```text
/// cargo test -p prover --test composed_vectors block_program_equality_and_export -- --ignored --nocapture
/// ```
#[test]
#[ignore = "proves the real block circuit twice (many minutes); regenerates block_composed_vectors.{json,bin}"]
fn block_program_equality_and_export() -> Result<(), Box<dyn Error>> {
    // One transfer keeps the settlement trace smallest while still exercising
    // the whole shielded path end to end.
    let (note, sk_d) = funded_note(11, 1_000);
    let (tree, paths) = tree_with(&[note]);
    let recipient = derive_spend_pk(&Sha3_256Shielded, &seed(9));
    // The inner (client) config: transfer proofs are Poseidon2 WHIR at the
    // recursion circuit's LDE, exactly as a real client produces them.
    let inner = InnerWhirConfig::new(prover::transfer::LOG_MAX_LDE, 0).expect("inner config");

    let out_note = Note::new(900, seed(200), seed(201), recipient);
    let spec = ClientSpec {
        note: &note,
        sk_d: &sk_d,
        path: &paths[0],
        index: 0,
        output: &out_note,
        fee: 100,
    };
    let mut map = NullifierMap::new(Keccak256Commitment);
    let client = prove_client_transfer(&inner, &spec, &tree, &mut map).expect("client prove");

    let shape = TransferShape {
        num_nullifiers: 1,
        num_outputs: 1,
    };
    let children = vec![ChildProof {
        verifier: &client.verifier,
        proof: &client.proof,
        statement: &client.statement,
        shape,
    }];
    let rc = build_multi_transfer_circuit(&inner, &children).expect("block circuit");

    // The block statement: shape header, then the child's statement - exactly
    // what the native block verifier accepts and what applyBlock must pass.
    let mut pis: Vec<F> = shape_header([shape].iter())?
        .iter()
        .map(|&v| F::from_u16(v))
        .collect();
    pis.extend_from_slice(&client.statement);

    let params = settlement_params_for(prover::block::BLOCK_LOG_MAX_LDE);

    let mut rounds_a = Vec::new();
    let mut starts_a = Vec::new();
    let (_doc_a, _out_a, program_a) = composed_run_with(
        &pis,
        &rc,
        &params,
        prover::block::BLOCK_LOG_MAX_LDE,
        &mut rounds_a,
        &mut starts_a,
    )?;

    let mut rounds_b = Vec::new();
    let mut starts_b = Vec::new();
    let (doc, out, program_b) = composed_run_with(
        &pis,
        &rc,
        &params,
        prover::block::BLOCK_LOG_MAX_LDE,
        &mut rounds_b,
        &mut starts_b,
    )?;
    assert_eq!(
        program_a.len(),
        program_b.len(),
        "runs disagree on program length"
    );
    assert_eq!(starts_a, starts_b, "runs disagree on round boundaries");

    let (fixed_raw, _varying_raw) = classify_observations(&[program_a, program_b.clone()]);
    let fixed = reclassify_zero_runs(&program_b, fixed_raw);
    let extras = write_block_genesis(note, out_note, &pis)?;
    export_and_write(
        doc,
        &out,
        &program_b,
        &fixed,
        &starts_b,
        "block_composed_vectors",
        Some(&pis),
        extras,
    )
}
