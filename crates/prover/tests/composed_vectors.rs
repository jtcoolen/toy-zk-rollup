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
//! batch_stark_vectors) and, at the delegate, runs its own WHIR core (ported in M1-M4
//! from the walk pinned by whir_proof_vectors). Neither pin alone proves the two halves
//! compose: the batch fixture hands the WHIR core a per-round statement (stacked config,
//! opening schedule, univariate points) that only exists at settlement shape, and the
//! WHIR fixture never sees the batch transcript around it.
//!
//! This test closes that gap. It proves the settlement batch under the semantic config,
//! replays the batch phases by hand, and inside transcript.delegate replaces the native
//! PCS with the shared WHIR walk: for each of the five opening rounds it rebuilds the
//! WHIR config and opening schedule from public ingredients (padded_arity,
//! checked_stacked_num_variables, univariate_eq_point - the same construction
//! round_schedule performs), drives verify_whir_round on the batch challenger, and
//! re-checks the claimed openings against the walk's bound evaluations with the
//! univariate-eq scales. one_run then asserts the combined event program equals the
//! native CircuitVerifier::verify run's - batch phases and WHIR core events alike.
//!
//! If the programs agree, the Solidity composition is mechanical assembly of pieces
//! each already pinned: BatchTranscript.sol up to the delegate, then WhirVerifierCore
//! per round with the statement exported here.
#![recursion_limit = "256"]

use std::error::Error;
use std::path::PathBuf;

use p3_field::{PrimeField32, TwoAdicField};
use p3_multilinear_util::point::Point;
use p3_recursion::pcs::whir::uni::plan::checked_stacked_num_variables;
use p3_recursion::pcs::whir::uni::{padded_arity, univariate_eq_point};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, OpeningRequest, TableShape, TableSpec};
use p3_whir::parameters::WhirConfig;
use serde_json::json;

use prover::semantic_blob::{classify_observations, replay_blob};
use prover::semantic_trace::{SemChallenger, SemProgram};
use prover::whir::FOLDING_FACTOR;

mod batch_fixture;
mod whir_walk;
use batch_fixture::{
    base_json, com_json, dom_json, ext_json, fib_recursion, hex, one_run, settlement_params,
    Challenge, Dft, OpeningClaims, OpeningProof, ReplayOut, SemPcs, CAP_HEIGHT,
};
use whir_walk::{verify_whir_round, RoundWalk, TerminalWalk, WhirRoundWalk};

/// A point as the contract reads it: one extension element per coordinate.
fn point_json(p: &Point<Challenge>) -> Vec<Vec<u32>> {
    p.as_slice().iter().map(ext_json).collect()
}

/// The per-round WHIR schedule as the contract sees it: one entry per WHIR round plus
/// the terminal configuration, derived from the rebuilt config exactly as the small-shape
/// artifact derives it.
fn schedule_json(config: &WhirConfig<Challenge, prover::F, SemChallenger>) -> serde_json::Value {
    let round = |r: &p3_whir::parameters::RoundConfig| {
        json!({
            "pow_bits": r.pow_bits,
            "folding_pow_bits": r.folding_pow_bits,
            "num_queries": r.num_queries,
            "ood_samples": r.ood_samples,
            "num_variables": r.num_variables,
            "folding_factor": r.folding_factor,
            "log_inv_rate": r.log_inv_rate,
            "domain_size": r.domain_size,
            "log_folded_domain_size": r.log_folded_domain_size,
            "folded_domain_gen": prover::F::two_adic_generator(r.log_folded_domain_size)
                .as_canonical_u32(),
        })
    };
    json!({
        "rounds": config.round_parameters().iter().map(round).collect::<Vec<_>>(),
        "final_round": round(&config.final_round_config()),
        "commitment_ood_samples": config.commitment_ood_samples(),
    })
}

fn exts(v: &[Challenge]) -> Vec<Vec<u32>> {
    v.iter().map(ext_json).collect()
}

fn exts2(v: &[Vec<Challenge>]) -> Vec<Vec<Vec<u32>>> {
    v.iter().map(|r| exts(r)).collect()
}

/// One round walk, fully serialized: everything WhirVerifierCore.sol needs to replay
/// the round and everything the Solidity tests need to check it against.
fn walk_json(walk: &WhirRoundWalk) -> serde_json::Value {
    let r: &RoundWalk = &walk.rounds;
    let t: &TerminalWalk = &walk.terminal;
    json!({
        "alpha": ext_json(&walk.alpha),
        "gamma": ext_json(&walk.gamma),
        "initial_claimed_eval": ext_json(&walk.initial_claimed_eval),
        "claimed_eval": ext_json(&walk.claimed_eval),
        "initial_randomness": exts(&walk.randomness),
        "num_variables": walk.num_variables,
        "eq_points": walk.eq_points.iter().map(point_json).collect::<Vec<_>>(),
        "eq_evals": exts(&walk.eq_evals),
        "eq_group_lens": walk.eq_group_lens,
        "initial_ood_answers": exts(&walk.initial_ood_answers),
        "initial_sumcheck_ca": exts(&walk.initial_sumcheck_ca),
        "initial_sumcheck_cinf": exts(&walk.initial_sumcheck_cinf),
        "last_root": hex(&walk.last_root),
        "bound_evals": exts2(&walk.bound_evals),
        "claim_widths": walk.claim_widths,
        "round_commitments": r.commitments.iter().map(|c| hex(c)).collect::<Vec<_>>(),
        "round_paths": r.paths.clone(),
        "rounds": {
            "claimed_evals": exts(&r.claimed_evals),
            "folded_claims": exts(&r.folded_claims),
            "folds": exts2(&r.folds),
            "ood_points": exts(&r.ood_points),
            "domain_points": r.domain_points,
            "round_batching": exts(&r.round_batching),
            "query_indices": r.query_indices,
            "round_randomness": exts2(&r.round_randomness),
            "ood_answers": exts2(&r.ood_answers),
            "pow_witnesses": r.pow_witnesses.iter().map(|w| base_json(*w)).collect::<Vec<_>>(),
            "sumcheck_ca": exts2(&r.sumcheck_ca),
            "sumcheck_cinf": exts2(&r.sumcheck_cinf),
            "rows_base": r.rows_base,
            "rows_ext": exts2(&r.rows_ext),
            "params": r.params.iter().map(|p| p.to_vec()).collect::<Vec<_>>(),
        },
        "round0_paths": walk.round0_paths,
        "terminal": {
            "query_indices": t.query_indices,
            "final_randomness": t.final_randomness.as_ref().map(|v| exts(v)),
            "final_poly": exts(&t.final_poly),
            "final_pow_witness": t.final_pow_witness,
            "final_rows_ext": exts2(&t.final_rows_ext),
            "final_paths": t.final_paths,
            "final_folds": exts(&t.final_folds),
            "final_domain_points": t.final_domain_points,
            "final_sumcheck_ca": exts(&t.final_sumcheck_ca),
            "final_sumcheck_cinf": exts(&t.final_sumcheck_cinf),
            "final_sumcheck_pow_witnesses": t.final_sumcheck_pow_witnesses,
            "claimed_before_final": ext_json(&t.claimed_before_final),
            "claimed_after_final": ext_json(&t.claimed_after_final),
        },
        "query_indices": walk.query_indices,
    })
}

/// One composed proving + verification run. The replacer runs inside
/// transcript.delegate: it rebuilds each round's WHIR statement from public
/// ingredients, drives the shared walk on the batch challenger, and re-checks the
/// claimed openings against the walk's bound evaluations - the rescale step
/// verify_rounds performs after verify_at.
fn composed_run(
    rounds_json: &mut Vec<serde_json::Value>,
    round_starts: &mut Vec<usize>,
) -> Result<(serde_json::Value, ReplayOut, SemProgram), Box<dyn Error>> {
    let (pis, rc) = fib_recursion();
    let params = settlement_params();

    {
        let mut replacer = |ch: &mut SemChallenger,
                            claims: &OpeningClaims,
                            proof: &OpeningProof,
                            _preprocessed_index: Option<usize>,
                            sink: &prover::semantic_trace::SemSink|
         -> Result<(), String> {
            for (round, (claim, round_proof)) in claims.iter().zip(&proof.rounds).enumerate() {
                // Record where this round's events begin in the combined program: the
                // delegate region splits per round, and the contract needs each round's
                // fixed-constant slice to generate (not read) its absorbs.
                let _ = sink;
                round_starts.push(sink.program().len());
                // The statement: shapes and per-matrix opening points, read off the
                // batch proof exactly as verify_rounds reads them.
                let mut shapes: Vec<(usize, usize)> = Vec::new();
                let mut points_per_matrix: Vec<Vec<Challenge>> = Vec::new();
                for matrix in &claim.matrices {
                    let width = matrix
                        .points
                        .first()
                        .map(|p| p.values.len())
                        .ok_or_else(|| format!("round {round}: matrix with no points"))?;
                    if matrix.points.iter().any(|p| p.values.len() != width) {
                        return Err(format!("round {round}: ragged opening widths"));
                    }
                    shapes.push((matrix.domain.log_size(), width));
                    points_per_matrix.push(matrix.points.iter().map(|p| p.point).collect());
                }
                let stacked =
                    checked_stacked_num_variables(shapes.iter().map(|&(log_height, width)| {
                        (padded_arity(log_height, FOLDING_FACTOR), width)
                    }))
                    .map_err(|e| format!("round {round}: stacked arity: {e:?}"))?;
                let config =
                    WhirConfig::<Challenge, prover::F, SemChallenger>::new(stacked, params.clone())
                        .map_err(|e| format!("round {round}: config: {e:?}"))?;

                // The schedule: identical construction to round_schedule, from public
                // ingredients only.
                let specs: Vec<TableSpec> = shapes
                    .iter()
                    .zip(&points_per_matrix)
                    .map(|(&(log_height, width), pts)| {
                        let schedule: Vec<OpeningRequest> = pts
                            .iter()
                            .map(|_| OpeningBatch::new((0..width).collect(), Vec::new()))
                            .collect();
                        TableSpec::new(TableShape::new(log_height, width), schedule)
                    })
                    .collect();
                let protocol = OpeningProtocol::new(specs).pad_to_min_num_variables(FOLDING_FACTOR);
                let mut points = Vec::new();
                let mut scales: Vec<Vec<Challenge>> = Vec::new();
                for (&(log_height, _), zetas) in shapes.iter().zip(&points_per_matrix) {
                    let arity = padded_arity(log_height, FOLDING_FACTOR).get();
                    let mut row = Vec::with_capacity(zetas.len());
                    for &zeta in zetas {
                        let (point, scale) = univariate_eq_point(zeta, arity);
                        points.push(point);
                        row.push(scale);
                    }
                    scales.push(row);
                }

                let root = <[u8; 32]>::try_from(claim.commitment.roots()[0].as_ref())
                    .expect("32-byte cap root");
                let walk = verify_whir_round(
                    ch,
                    round_proof,
                    &config,
                    &protocol,
                    &points,
                    &Dft::default(),
                    CAP_HEIGHT,
                    &root,
                )
                .map_err(|e| format!("round {round}: walk: {e}"))?;

                // The rescale check: claimed == bound * eq-scale, matrix-major then
                // point, matching the schedule order.
                let mut batch = 0usize;
                for (m, matrix) in claim.matrices.iter().enumerate() {
                    for (p, pt) in matrix.points.iter().enumerate() {
                        let bound = round_proof
                            .evals
                            .get(batch)
                            .ok_or_else(|| format!("round {round}: missing bound {batch}"))?;
                        if bound.current().len() != pt.values.len() {
                            return Err(format!("round {round}: bound width mismatch"));
                        }
                        for (col, (&b, &c)) in bound.current().iter().zip(&pt.values).enumerate() {
                            if b * scales[m][p] != c {
                                return Err(format!(
                                    "round {round}: opening mismatch batch {batch} col {col}"
                                ));
                            }
                        }
                        batch += 1;
                    }
                }

                rounds_json.push(json!({
                    "commitment": com_json(&claim.commitment),
                    "stacked_num_variables": stacked,
                    "matrices": claim.matrices.iter().map(|m| json!({
                        "domain": dom_json(&m.domain),
                        "points": m.points.iter().map(|pt| json!({
                            "point": ext_json(&pt.point),
                            "values": pt.values.iter().map(ext_json).collect::<Vec<_>>(),
                        })).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                    "schedule_points": points.iter().map(point_json).collect::<Vec<_>>(),
                    "scales": scales.iter().map(|row| exts(row)).collect::<Vec<_>>(),
                    "schedule": schedule_json(&config),
                    "walk": walk_json(&walk),
                }));
            }
            Ok(())
        };
        let (program, out, _verifier, _proof) = one_run(&pis, &rc, Some(&mut replacer));
        let doc = json!({
            "description": "composed settlement-shape WHIR walk: the shared walk driven
                inside the batch delegate at the real opening shapes; program equality
                against the native run is asserted by one_run",
            "field": "KoalaBear",
            "folding_factor": FOLDING_FACTOR,
            "num_rounds": rounds_json.len(),
            "rounds": rounds_json,
            "zeta": ext_json(&out.zeta),
            "program_len": program.len(),
            "round_starts": round_starts.clone(),
            "phase_marks": out
                .phase_marks
                .iter()
                .map(|(name, at)| json!({"phase": name, "at": at}))
                .collect::<Vec<_>>(),
        });
        Ok((doc, out, program))
    }
}

/// Fixed-constant word count per round region: how many constant words the contract's
/// constant payload must supply to each round, derived from the classification. The
/// Solidity side asserts it consumed exactly this many, so a schedule drift fails loud.
fn round_const_words(
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    starts: &[usize],
) -> Vec<usize> {
    let end_of = |r: usize| starts.get(r + 1).copied().unwrap_or(program.len());
    starts
        .iter()
        .enumerate()
        .map(|(r, &start)| {
            (start..end_of(r))
                .filter_map(|i| fixed[i].as_ref().map(|v| v.len()))
                .sum()
        })
        .collect()
}

/// The linchpin: prove, verify natively, replay the batch phases with the shared WHIR
/// walk in the delegate, and require the combined programs to agree (asserted inside
/// one_run). Then export the per-round statements and the composed blob for Solidity.
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

    let (fixed, varying) = classify_observations(&[program_a.clone(), program_b.clone()]);
    let blob = replay_blob(&program_b, &fixed).expect("composed blob");
    let const_words = round_const_words(&program_b, &fixed, &starts_b);

    let mut doc = doc;
    doc["varying_positions"] = json!(varying);
    doc["round_const_words"] = json!(const_words);
    doc["blob_len"] = json!(blob.len());
    doc["phase_marks_before_delegate"] = json!(out
        .phase_marks
        .iter()
        .find(|(n, _)| n == "before_delegate")
        .map(|(_, at)| *at));

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    std::fs::create_dir_all(&dir).expect("vectors dir");
    std::fs::write(
        dir.join("composed_vectors.json"),
        serde_json::to_string_pretty(&doc).expect("serialize"),
    )
    .expect("write json");
    std::fs::write(dir.join("composed_vectors.bin"), &blob).expect("write bin");
    println!(
        "wrote composed_vectors.json: {} rounds, program {} events, blob {} bytes, {} fixed runs, const words {:?}",
        doc["num_rounds"].as_u64().unwrap(),
        doc["program_len"].as_u64().unwrap(),
        blob.len(),
        fixed.iter().filter(|f| f.is_some()).count(),
        const_words,
    );
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
        assert!(r["walk"]["rounds"]["params"].as_array().unwrap().len() >= 1);
        assert!(r["schedule"]["rounds"].as_array().unwrap().len() >= 1);
    }
    // The ZK PCS type flag guards the randomization round: with ZK on, round 0 is
    // the randomization commitment and there are five rounds; without it the shape
    // pin above would already be wrong, but assert the flag too.
    assert!(<SemPcs as p3_commit::UnivariateStarkPcs<Challenge, SemChallenger>>::ZK);
}
