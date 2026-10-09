//! The composed settlement export: prove a recursion circuit under the
//! semantic config, drive the shared WHIR walk inside the batch delegate,
//! and emit the composed artifact (JSON doc + semantic blob) the WBND
//! encoder turns into calldata. Moved from `tests/composed_vectors` so the
//! node can produce the same artifact at runtime.

// Infallible-by-construction unwraps: every expect here parses JSON this
// crate itself just produced (or fixed-shape blob bytes), so a failure is
// a bug in the producer, not an input condition. Same precedent as fixtures.rs.
// Doc-style lints (long doc paragraphs, # Errors/# Panics sections, arg/line
// counts) are noise on this generated-artifact machinery: the functions are
// internal encoders whose contracts are pinned by byte-identity tests.
#![allow(
    clippy::too_long_first_doc_paragraph,
    clippy::doc_overindented_list_items,
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::cast_possible_truncation
)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use std::error::Error;
use std::path::PathBuf;

use p3_field::{PrimeField32, TwoAdicField};
use p3_multilinear_util::point::Point;
use p3_recursion::pcs::whir::uni::plan::checked_stacked_num_variables;
use p3_recursion::pcs::whir::uni::{padded_arity, univariate_eq_point};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, OpeningRequest, TableShape, TableSpec};
use p3_whir::parameters::WhirConfig;
use serde_json::json;

use p3_air::symbolic::AirLayout;
use p3_air::BaseAir;
use p3_circuit_prover::CircuitVerifier;
use p3_lookup::LogUpGadget;

use crate::constraint_ir::{instance_identity_json, EF};
use crate::semantic_blob::replay_blob;
use crate::semantic_trace::{SemChallenger, SemEvent, SemProgram};
use crate::settlement_replay::{
    base_json, bus_layout, com_json, dom_json, ext_json, fib_recursion, hex, one_run_for_seed,
    settlement_params, settlement_params_for, Challenge, Dft, OpeningClaims, OpeningProof,
    ReplayOut, SemConfig, CAP_HEIGHT,
};
use crate::whir::folding_factor_final;
use crate::whir_recursion::{RecursionCircuit, LOG_MAX_LDE};
use crate::whir_walk::{verify_whir_round, RoundWalk, TerminalWalk, WhirRoundWalk};
use crate::F;

/// A point as the contract reads it: one extension element per coordinate.
pub fn point_json(p: &Point<Challenge>) -> Vec<Vec<u32>> {
    p.as_slice().iter().map(ext_json).collect()
}

/// The per-round WHIR schedule as the contract sees it: one entry per WHIR round plus
/// the terminal configuration, derived from the rebuilt config exactly as the small-shape
/// artifact derives it.
#[must_use]
pub fn schedule_json(config: &WhirConfig<Challenge, crate::F, SemChallenger>) -> serde_json::Value {
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
            "folded_domain_gen": crate::F::two_adic_generator(r.log_folded_domain_size)
                .as_canonical_u32(),
        })
    };
    json!({
        "rounds": config.round_parameters().iter().map(round).collect::<Vec<_>>(),
        "final_round": round(&config.final_round_config()),
        "commitment_ood_samples": config.commitment_ood_samples(),
        "starting_folding_pow_bits": config.starting_folding_pow_bits(),
    })
}

/// Extension elements as canonical basis-coefficient triples of lists.
pub fn exts(v: &[Challenge]) -> Vec<Vec<u32>> {
    v.iter().map(ext_json).collect()
}

/// Nested extension elements (per-round lists) as canonical coefficients.
#[must_use]
pub fn exts2(v: &[Vec<Challenge>]) -> Vec<Vec<Vec<u32>>> {
    v.iter().map(|r| exts(r)).collect()
}

/// One round walk, fully serialized: everything WhirVerifierCore.sol needs to replay
/// the round and everything the Solidity tests need to check it against.
pub fn walk_json(walk: &WhirRoundWalk) -> serde_json::Value {
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
        "initial_sumcheck_pow_witnesses": walk.initial_sumcheck_pow_witnesses.clone(),
        "last_root": hex(&walk.last_root),
        "bound_evals": exts2(&walk.bound_evals),
        "claim_widths": walk.claim_widths,
        "phase_offsets": walk.phase_offsets,
        "round_commitments": r.commitments.iter().map(|c| hex(c)).collect::<Vec<_>>(),
        "round_paths": r.paths.clone(),
            "round_pruned_paths": r.pruned_paths.clone(),
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
            "sumcheck_pow_witnesses": r.sumcheck_pow_witnesses.clone(),
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
                "final_pruned_paths": t.final_pruned_paths,
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
/// `verify_rounds` performs after `verify_at`.
pub fn composed_run(
    rounds_json: &mut Vec<serde_json::Value>,
    round_starts: &mut Vec<usize>,
) -> Result<(serde_json::Value, ReplayOut, SemProgram), Box<dyn Error>> {
    let (pis, rc) = fib_recursion();
    let params = settlement_params();
    composed_run_with(
        &pis,
        &rc,
        &params,
        LOG_MAX_LDE,
        1,
        rounds_json,
        round_starts,
    )
}

/// The constraint-identity block for one settlement batch, built from the SAME
/// proof run whose transcript events the bundle ships (a second run would mask
/// fresh randomness and desynchronize the pins from the bundle bytes).
///
/// Per instance this carries the flattened constraint program, the trusted
/// domain parameters, every opened value the fold consumes, and the two pins
/// (fold * `inv_vanishing` == quotient, inversion-free quotient reformulation),
/// see `constraint_ir::instance_identity_json`. The Solidity verifier evaluates
/// the program on opened values it derives from the WHIR rounds themselves,
/// and the pin test replays this JSON against the same program.
pub fn constraint_identity_block(
    verifier: &CircuitVerifier<SemConfig>,
    proof: &p3_circuit_prover::BatchStarkProof<SemConfig>,
    out: &ReplayOut,
    pis: &[F],
) -> Result<serde_json::Value, Box<dyn Error>> {
    let common = verifier.common_data();
    let airs = verifier
        .table_airs::<4>()
        .map_err(|e| Box::<dyn Error>::from(format!("table_airs: {e:?}")))?;
    let public_values = verifier
        .table_public_values(pis)
        .map_err(|e| Box::<dyn Error>::from(format!("table_public_values: {e:?}")))?;
    let gadget = LogUpGadget::new();
    let (bus_ids, max_message_width, _) = bus_layout(&common.lookups);
    let mut instances = Vec::new();
    for (i, air) in airs.iter().enumerate() {
        let layout = AirLayout {
            preprocessed_width: out.preprocessed_widths[i],
            main_width: BaseAir::<F>::width(air),
            num_public_values: BaseAir::<F>::num_public_values(air),
            num_periodic_columns: BaseAir::<F>::num_periodic_columns(air),
            ..Default::default()
        };
        let perm_values: Vec<EF> = proof
            .proof
            .lookup_terminals
            .get(i)
            .and_then(Option::as_ref)
            .map(|t| vec![t.0])
            .unwrap_or_default();
        instances.push(instance_identity_json::<SemConfig, _>(
            i,
            air,
            layout,
            common.lookups[i].as_ref(),
            &proof.proof.opened_values.instances[i],
            &public_values[i],
            out.trace_domains[i],
            &out.quotient_domains[i],
            &out.challenges[i],
            &perm_values,
            out.zeta,
            out.constraint_alpha,
            &gadget,
        ));
    }
    Ok(json!({
        "description": "constraint identity: programs + opened values + pins, from the same proof run as the bundle",
        "zeta": ext_json(&out.zeta),
        "constraint_alpha": ext_json(&out.constraint_alpha),
        "statement_instance": json!(verifier.statement_layout().table_instance()),
        "bus_ids": json!(bus_ids),
        "max_message_width": json!(max_message_width),
        "terminal_counts": json!(proof.proof.lookup_terminals.iter().map(Option::is_some).collect::<Vec<_>>()),
        "instances": json!(instances),
    }))
}

/// The composed run at an explicit circuit + settlement shape. The Fibonacci
/// recursion circuit and the real shielded block circuit differ in both, but the
/// composition claim is the same: the shared WHIR walk inside the batch delegate
/// reproduces the native PCS's transcript event-for-event.
pub fn composed_run_with(
    pis: &[F],
    rc: &RecursionCircuit,
    params: &p3_whir::parameters::ProtocolParameters,
    log_max_lde: usize,
    rate: usize,
    rounds_json: &mut Vec<serde_json::Value>,
    round_starts: &mut Vec<usize>,
) -> Result<(serde_json::Value, ReplayOut, SemProgram), Box<dyn Error>> {
    composed_run_with_seed(pis, rc, params, log_max_lde, rate, 0, rounds_json, round_starts)
}

/// `composed_run_with` under a perturbed Fiat-Shamir initial state (see
/// `crate::settlement_replay::sem_challenger_with_seed`). Same circuit, statement
/// and witness; only the challenge stream differs. Two seeds produce program
/// *twins*: identical shape (length, round starts, event kinds, grind counts)
/// with every witness-dependent value different. Diffing a pair separates fixed
/// framing constants from varying proof data in the delegate region - the
/// replacement for the old two-run blinding diff, which died with settlement
/// blinding.
pub fn composed_run_with_seed(
    pis: &[F],
    rc: &RecursionCircuit,
    params: &p3_whir::parameters::ProtocolParameters,
    log_max_lde: usize,
    rate: usize,
    seed: u64,
    rounds_json: &mut Vec<serde_json::Value>,
    round_starts: &mut Vec<usize>,
) -> Result<(serde_json::Value, ReplayOut, SemProgram), Box<dyn Error>> {
    {
        let mut replacer = |ch: &mut SemChallenger,
                            claims: &OpeningClaims,
                            proof: &OpeningProof,
                            _preprocessed_index: Option<usize>,
                            sink: &crate::semantic_trace::SemSink|
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
                        (padded_arity(log_height, folding_factor_final()), width)
                    }))
                    .map_err(|e| format!("round {round}: stacked arity: {e:?}"))?;
                let config =
                    WhirConfig::<Challenge, crate::F, SemChallenger>::new(stacked, params.clone())
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
                let protocol = OpeningProtocol::new(specs).pad_to_min_num_variables(folding_factor_final());
                let mut points = Vec::new();
                let mut scales: Vec<Vec<Challenge>> = Vec::new();
                for (&(log_height, _), zetas) in shapes.iter().zip(&points_per_matrix) {
                    let arity = padded_arity(log_height, folding_factor_final()).get();
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
                        "arity": padded_arity(m.domain.log_size(), folding_factor_final()).get(),
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
        let (program, out, verifier, proof) =
            one_run_for_seed(pis, rc, Some(&mut replacer), log_max_lde, rate, seed);
        let constraint_identity = constraint_identity_block(&verifier, &proof, &out, pis)?;
        let doc = json!({
            "description": "composed settlement-shape WHIR walk: the shared walk driven
                inside the batch delegate at the real opening shapes; program equality
                against the native run is asserted by one_run",
            "field": "KoalaBear",
            "folding_factor": folding_factor_final(),
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
            "constraint_identity": constraint_identity,
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
                .filter_map(|i| fixed[i].as_ref().map(std::vec::Vec::len))
                .sum()
        })
        .collect()
}

/// Segment each round region's config-fixed absorbs into runs, exactly as
/// `whir_proof_vectors::fixed_runs` does for a whole program but scoped to one
/// round's event range. Each run is the concatenation of consecutive fixed
/// constant words as a little-endian hex string; run boundaries are the
/// proof-dependent (varying) absorbs that interrupt them. The contract's
/// constant payload is the concatenation of these runs in order, and the run
/// lengths are the per-site absorb counts it must reproduce: verifyInitial's
/// preClaims/perClaim/batching/sumcheck sites and each WHIR round's separator
/// sites. At settlement shape the per-claim run is width-dependent (the eq
/// point expansion grows with the claim's column count), so the small-shape
/// scalar schedule does not generalize and the contract reads these lengths
/// instead of deriving them.
fn round_fixed_runs(
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    starts: &[usize],
) -> Vec<Vec<String>> {
    let end_of = |r: usize| starts.get(r + 1).copied().unwrap_or(program.len());
    starts
        .iter()
        .enumerate()
        .map(|(r, &start)| {
            let mut runs: Vec<String> = Vec::new();
            let mut current: Vec<u8> = Vec::new();
            for i in start..end_of(r) {
                if matches!(
                    program[i],
                    SemEvent::ObserveBase { .. } | SemEvent::ObserveBytes { .. }
                ) {
                    if let Some(words) = &fixed[i] {
                        current.extend(words.iter().flat_map(|w| w.to_le_bytes()));
                        continue;
                    }
                }
                if !current.is_empty() {
                    runs.push(hex(&current));
                    current.clear();
                }
            }
            if !current.is_empty() {
                runs.push(hex(&current));
            }
            runs
        })
        .collect()
}

/// Reclassify every all-zero fixed run as varying (proof data). See the call
/// site for why: a run of zero words is a structurally-zero extension element,
/// not a framing constant, and the contract must read it from calldata.
#[must_use]
pub fn reclassify_zero_runs(
    program: &SemProgram,
    fixed: Vec<Option<Vec<u32>>>,
) -> Vec<Option<Vec<u32>>> {
    let mut out = fixed;
    let mut i = 0usize;
    while i < program.len() {
        let starts_run = matches!(
            program[i],
            SemEvent::ObserveBase { .. } | SemEvent::ObserveBytes { .. }
        ) && out[i].is_some();
        if !starts_run {
            i += 1;
            continue;
        }
        // Walk the maximal fixed run.
        let begin = i;
        let mut all_zero = true;
        while i < program.len()
            && matches!(
                program[i],
                SemEvent::ObserveBase { .. } | SemEvent::ObserveBytes { .. }
            )
            && out[i].is_some()
        {
            if out[i].as_ref().is_some_and(|w| w.iter().any(|&x| x != 0)) {
                all_zero = false;
            }
            i += 1;
        }
        if all_zero {
            for slot in &mut out[begin..i] {
                *slot = None;
            }
        }
    }
    out
}

/// The positions the contract reads from calldata: every observation the
/// corrected classification marks varying.
fn varying_positions(program: &SemProgram, fixed: &[Option<Vec<u32>>]) -> Vec<usize> {
    (0..program.len()).filter(|&i| fixed[i].is_none()).collect()
}

/// D-092 batch 89: the structural fixed/varying classification for the batch
/// (pre-delegate) region, derived from the phase marks instead of a diff of two
/// settlement proofs.
///
/// With settlement blinding off (`Pcs::ZK = false`) two runs over the same
/// circuit and statement are byte-identical, so `classify_observations` marks
/// every position fixed and the batch digests - which the contract must read
/// from the proof section - collapse into the trusted constant table (the
/// wbnd walk then panics with no main digest). The classification is not a
/// property of the run pair; it is a property of the protocol:
///
/// * `ObserveBase` before the end of `main_phase` is the domain seed, the
///   claimed degree, and the statement's public values - fixed per block, so
///   they ride in the bundle's constant section (the bundle is per block).
/// * The single `ObserveBytes` digest inside `preprocessed_phase` is the
///   trusted-setup commitment - fixed.
/// * Every other observation is proof data: the main/permutation/quotient
///   commitment digests, the permutation terminals, and everything from the
///   delegate onward (round regions absorb only client-proof-dependent values
///   once blinding is off, so the whole delegate region is varying; the
///   framing tables and claim schedules degrade to single varying runs, which
///   the contract consumes as data - the bundle bytes are identical either
///   way, only the section each word rides in changes).
///
/// Marks are END positions: the phase of a site is the first mark whose end
/// exceeds it, matching the wbnd walk's `phase_of`.
#[must_use]
pub fn structural_batch_fixed(
    program: &SemProgram,
    marks: &[(String, usize)],
) -> Vec<Option<Vec<u32>>> {
    let mark_at = |name: &str| -> Option<usize> {
        marks.iter().find(|(n, _)| n == name).map(|(_, at)| *at)
    };
    let main_end = mark_at("main_phase").unwrap_or(usize::MAX);
    let delegate = mark_at("before_delegate").unwrap_or(program.len());
    let mut sorted: Vec<(usize, &str)> = marks.iter().map(|(n, at)| (*at, n.as_str())).collect();
    sorted.sort_by_key(|(at, _)| *at);
    let phase_of = |site: usize| -> &str {
        sorted
            .iter()
            .find(|(at, _)| *at > site)
            .map_or("after", |(_, name)| name)
    };
    program
        .iter()
        .enumerate()
        .map(|(i, event)| {
            if i >= delegate {
                return None;
            }
            match event {
                SemEvent::ObserveBase { value } if i < main_end => Some(vec![*value]),
                SemEvent::ObserveBytes { bytes } if phase_of(i) == "preprocessed_phase" => {
                    Some(
                        bytes
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .copied()
                            .map(u32::from_le_bytes)
                            .collect(),
                    )
                }
                _ => None,
            }
        })
        .collect()
}

/// The Fiat-Shamir seed for the classification twin. Seed 0 is the production
/// transcript (empty initial state); seed 1 perturbs every challenge while
/// leaving the program shape identical.
pub const TWIN_SEED: u64 = 0x5EED_092;

/// Fixed/varying classification from a seed-twin pair: two settlement runs over
/// the same circuit, statement and witness under two Fiat-Shamir seeds.
///
/// The batch (pre-delegate) region keeps the structural rule - those observations
/// are block-public values (seed, degree, public values, preprocessed digest)
/// that no seed perturbation changes, and the wbnd walk needs the batch digests
/// classified as proof data. In the delegate region the diff decides: an
/// `ObserveBase`/`ObserveBytes` event whose value is identical under both seeds
/// is protocol framing (keccak labels, shape constants) or a config-determined
/// constant evaluation - fixed, absorbed from the trusted table. A value that
/// differs is witness- or challenge-dependent (claimed evaluations, Merkle
/// digests, grind witnesses) - varying, read from the proof section. Samples,
/// checks and grinds are never fixed.
///
/// This replaces the old two-run blinding diff: with settlement blinding off two
/// production runs are byte-identical, but a seed perturbation changes every
/// challenge (zeta, alphas, query indices) so every witness-dependent value
/// moves while the framing labels - derived from config, not from the
/// transcript - stay put.
///
/// Panics if the twins differ in shape: that would mean the seed leaked into a
/// control decision (grind length, phase order), which the sink design forbids.
#[must_use]
pub fn twin_delegate_fixed(
    program_a: &SemProgram,
    program_b: &SemProgram,
    marks: &[(String, usize)],
) -> Vec<Option<Vec<u32>>> {
    assert_eq!(
        program_a.len(),
        program_b.len(),
        "twin programs differ in length: seed perturbed a control decision"
    );
    let delegate = marks
        .iter()
        .find(|(n, _)| n == "before_delegate")
        .map_or(program_a.len(), |(_, at)| *at);
    let structural = structural_batch_fixed(program_a, marks);
    structural
        .into_iter()
        .enumerate()
        .map(|(i, slot)| {
            if i < delegate {
                return slot;
            }
            if program_a[i] != program_b[i] {
                return None;
            }
            match &program_a[i] {
                SemEvent::ObserveBase { value } => Some(vec![*value]),
                SemEvent::ObserveBytes { bytes } => Some(
                    bytes
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .copied()
                        .map(u32::from_le_bytes)
                        .collect(),
                ),
                _ => None,
            }
        })
        .collect()
}

/// The twin-composed settlement run: prove and verify under seed 0 (the
/// production transcript whose proof the bundle ships), prove a second
/// settlement under `TWIN_SEED` purely as a classification oracle, and return
/// the merged fixed/varying split alongside seed 0's doc, replay output,
/// program and round starts.
///
/// Cost: two settlement proofs per call - the same cost the pre-blinding-off
/// design paid for its two-run diff. The node pays this once per block.
#[allow(clippy::type_complexity)]
pub fn composed_run_twin(
    pis: &[F],
    rc: &RecursionCircuit,
    params: &p3_whir::parameters::ProtocolParameters,
    log_max_lde: usize,
    rate: usize,
) -> Result<
    (
        serde_json::Value,
        ReplayOut,
        SemProgram,
        Vec<Option<Vec<u32>>>,
        Vec<usize>,
    ),
    Box<dyn Error>,
> {
    let mut rounds_a = Vec::new();
    let mut starts_a = Vec::new();
    let (doc, out, program_a) =
        composed_run_with_seed(pis, rc, params, log_max_lde, rate, 0, &mut rounds_a, &mut starts_a)?;
    let mut rounds_b = Vec::new();
    let mut starts_b = Vec::new();
    let (_doc_b, _out_b, program_b) = composed_run_with_seed(
        pis,
        rc,
        params,
        log_max_lde,
        rate,
        TWIN_SEED,
        &mut rounds_b,
        &mut starts_b,
    )?;
    assert_eq!(starts_a, starts_b, "twin round starts differ");
    let fixed_raw = twin_delegate_fixed(&program_a, &program_b, &out.phase_marks);
    let fixed = reclassify_zero_runs(&program_a, fixed_raw);
    Ok((doc, out, program_a, fixed, starts_a))
}

/// Per-claim run schedule for one composed round: for each opening claim,
/// the alternating [`is_constant`, words] runs of its transcript region,
/// derived from the sink phase offsets and the fixed classification. This is
/// the contract's initial-phase walk plan: absorb `words` constant words from
/// the trusted table, then observe `words/4` extension evals from the proof,
/// alternating. Constant eval runs are structurally-constrained columns whose
/// values are config-determined (nonzero, trusted); varying eval runs are the
/// proof's claimed evaluations. The raggedness (trailing and mid-claim
/// constant runs) is invisible to any scalar schedule and must ship as data.
fn claim_run_schedule(
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    phase_offsets: &[usize],
) -> Vec<Vec<[usize; 2]>> {
    // phase_offsets[0] is the claims start; offsets[1..=n] are the claim ends.
    // Only the first `n` windows are claim regions; later windows cross into the
    // batching draw and sumcheck, which carry samples and are not claim framing.
    let mut out: Vec<Vec<[usize; 2]>> = Vec::new();
    for w in phase_offsets.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a >= b {
            out.push(Vec::new());
            continue;
        }
        let mut runs: Vec<[usize; 2]> = Vec::new();
        let mut i = a;
        while i < b {
            // A claim region is all observe events; a non-observe event (a
            // sample crossing a window boundary) is treated as one varying word
            // so the cursor always advances and the walk cannot spin.
            let is_observe = matches!(
                program[i],
                SemEvent::ObserveBase { .. } | SemEvent::ObserveBytes { .. }
            );
            let is_const = is_observe && fixed[i].is_some();
            let kind = usize::from(is_const);
            let mut words = 0usize;
            while i < b {
                let same = matches!(
                    program[i],
                    SemEvent::ObserveBase { .. } | SemEvent::ObserveBytes { .. }
                ) && usize::from(fixed[i].is_some()) == kind;
                if !same {
                    break;
                }
                words += fixed[i].as_ref().map_or(1, std::vec::Vec::len);
                i += 1;
            }
            if words == 0 {
                // Non-observe boundary event: one varying word, advance once.
                runs.push([0, 1]);
                i += 1;
                continue;
            }
            if let Some(last) = runs.last_mut() {
                if last[0] == kind {
                    last[1] += words;
                    continue;
                }
            }
            runs.push([kind, words]);
        }
        out.push(runs);
    }
    out
}

/// The curated framing table for one composed round: the constant words the
/// contract absorbs via `absorbConstants`, in the order its phases consume
/// them, with the constant EVALUATIONS excluded (those are proof data the
/// contract reads from calldata, not framing).
///
/// Walks the region's maximal runs. A fixed run before the claims is the
/// pre-claims framing; inside a claim span the first fixed run is that claim's
/// framing and any later fixed run is a constant evaluation (dropped); after
/// the last claim every fixed run is framing (batching, then one sumcheck
/// separator per sumcheck: initial, each intermediate round, terminal).
///
/// Returns the concatenated little-endian hex of the kept words plus the
/// per-category word counts: segments before the claims (split at dropped
/// events), one total per claim, and the post-claim segments (batching first,
/// then one sumcheck separator per sumcheck). The contract slices the hex by
/// these counts in phase order.
#[derive(Debug)]
pub(crate) struct FramingTable {
    pub hex: String,
    pub pre_claims: Vec<usize>,
    pub claim_framings: Vec<usize>,
    pub batching: usize,
    pub seps: Vec<usize>,
}

fn round_framing_table(
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    start: usize,
    end: usize,
    phase_offsets: &[usize],
    claim_widths: &[usize],
) -> FramingTable {
    // phase_offsets = [claims_start, claim_end_0, ..., claim_end_{n-1}].
    // Classify each fixed EVENT as framing or constant-eval, then emit the
    // framing events in program order as contiguous segments. A fixed event is
    // framing iff it is before the claims, after the last claim, or within a
    // claim's framing prefix (the leading fixed events of that claim, before its
    // first varying event). A fixed event after a claim's varying evals is a
    // constant evaluation - proof data the contract reads from calldata - even
    // when it is physically adjacent to the next claim's framing (the two runs
    // merge into one maximal fixed run, so a run-level boundary test would drop
    // the next claim's framing; the event-level test splits them correctly).
    let claims_start = *phase_offsets.first().unwrap_or(&start);
    let last_claim_end = *phase_offsets.last().unwrap_or(&start);
    let is_fixed_ev = |i: usize| {
        matches!(
            program[i],
            SemEvent::ObserveBase { .. } | SemEvent::ObserveBytes { .. }
        ) && fixed[i].is_some()
    };
    let event_words = |i: usize| fixed[i].as_ref().map_or(1, std::vec::Vec::len);
    // Per-claim framing length in WORDS: the claim region holds exactly
    // 4 * width words of evaluations (the contract reads them from calldata
    // via bound_evals, whether the eval is seed-varying or a seed-invariant
    // constant riding the same wire slot); everything else in the region is
    // framing absorbed from the trusted table. A fixed eval adjacent to the
    // leading fixed run must NOT be counted as framing or it is absorbed
    // twice - once from the table, once from calldata - shifting the
    // transcript and failing the first grind check.
    let mut framing_prefix: Vec<usize> = Vec::new();
    for (c, w) in phase_offsets.windows(2).enumerate() {
        let (a, b) = (w[0], w[1]);
        let mut region_words = 0usize;
        let mut i = a;
        while i < b {
            region_words += event_words(i);
            i += 1;
        }
        let evals_words = 4 * claim_widths.get(c).copied().unwrap_or(0);
        assert!(
            region_words >= evals_words,
            "claim {}: region {} words < eval {} words",
            c,
            region_words,
            evals_words
        );
        framing_prefix.push(region_words - evals_words);
    }
    // Claim index for a position: the c with phase_offsets[c] <= i < offsets[c+1].
    let claim_of = |i: usize| -> Option<usize> {
        (0..framing_prefix.len()).find(|&c| i >= phase_offsets[c] && i < phase_offsets[c + 1])
    };
    // Category of a kept event: Pre (before the claims), Claim(c) (inside
    // claim c's framing prefix), or Post (after the last claim). Adjacent kept
    // events in the same category accumulate into one bucket; a dropped event
    // or a category change closes the bucket. Pre and Post buckets stay split
    // (the contract walks them as separate absorb calls); per-claim buckets
    // are one total each regardless of splits, because the contract absorbs
    // each claim's framing as a single block before that claim's evals.
    enum Cat {
        Pre,
        Claim(usize),
        Post,
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut pre_claims: Vec<usize> = Vec::new();
    let mut claim_framings: Vec<usize> = vec![0; framing_prefix.len()];
    let mut post: Vec<usize> = Vec::new();
    // Per-claim walk state: words of framing consumed, and whether a varying
    // event has closed the claim's framing prefix.
    let mut framing_used: Vec<usize> = vec![0; framing_prefix.len()];
    let mut seen_varying: Vec<bool> = vec![false; framing_prefix.len()];
    // Current open bucket: (category, words). Claim buckets never close early.
    let mut open: Option<(Cat, usize)> = None;
    let close = |open: &mut Option<(Cat, usize)>, pre: &mut Vec<usize>, post: &mut Vec<usize>| {
        if let Some((cat, w)) = open.take() {
            match cat {
                Cat::Pre => pre.push(w),
                Cat::Post => post.push(w),
                Cat::Claim(_) => {}
            }
        }
    };
    let mut i = start;
    while i < end {
        if !is_fixed_ev(i) {
            if let Some(c) = claim_of(i) {
                seen_varying[c] = true;
            }
            close(&mut open, &mut pre_claims, &mut post);
            i += 1;
            continue;
        }
        let words = fixed[i].as_ref().map_or(1, std::vec::Vec::len);
        let cat = if i < claims_start {
            Some(Cat::Pre)
        } else if i >= last_claim_end {
            Some(Cat::Post)
        } else if let Some(c) = claim_of(i) {
            // Framing iff inside the claim's leading fixed prefix, measured in
            // words (see framing_prefix). Once a varying event has been seen
            // in the claim, later fixed events are constant evaluations.
            if seen_varying[c] {
                None
            } else if framing_used[c] < framing_prefix[c] {
                Some(Cat::Claim(c))
            } else {
                None
            }
        } else {
            None
        };
        match cat {
            Some(Cat::Claim(c)) => {
                assert!(
                    framing_used[c] + words <= framing_prefix[c],
                    "claim {}: framing cut lands mid-event ({} + {} > {})",
                    c,
                    framing_used[c],
                    words,
                    framing_prefix[c]
                );
                if let Some(ws) = &fixed[i] {
                    for w in ws {
                        bytes.extend(w.to_le_bytes());
                    }
                }
                // Claim framing absorbs as one block per claim: total the
                // words, no segment splits. Close any open pre/post bucket.
                close(&mut open, &mut pre_claims, &mut post);
                framing_used[c] += words;
                claim_framings[c] += words;
            }
            Some(cat) => {
                if let Some(ws) = &fixed[i] {
                    for w in ws {
                        bytes.extend(w.to_le_bytes());
                    }
                }
                match (&mut open, &cat) {
                    (Some((Cat::Pre, w0)), Cat::Pre) => *w0 += words,
                    (Some((Cat::Post, w0)), Cat::Post) => *w0 += words,
                    _ => {
                        close(&mut open, &mut pre_claims, &mut post);
                        open = Some((cat, words));
                    }
                }
            }
            None => close(&mut open, &mut pre_claims, &mut post),
        }
        i += 1;
    }
    close(&mut open, &mut pre_claims, &mut post);
    for c in 0..framing_prefix.len() {
        assert_eq!(
            claim_framings[c], framing_prefix[c],
            "claim {}: framing emitted {} words, expected {}",
            c, claim_framings[c], framing_prefix[c]
        );
    }
    FramingTable {
        hex: hex(&bytes),
        pre_claims,
        claim_framings,
        batching: *post.first().unwrap_or(&0),
        seps: post.iter().skip(1).copied().collect(),
    }
}

/// The full alternating run schedule of one round region: every maximal run
/// of constant (fixed) or varying observations as `[is_constant, words]`
/// pairs, in order. This is the contract's walk plan: absorb `words` constant
/// words from the trusted table, then read `words` words of proof data from
/// calldata, alternating. The constant runs' VALUES are in `round_fixed_runs`;
/// the varying runs' values are the proof payload in order. Deriving the
/// schedule from shapes alone does not generalize at settlement shape (the
/// per-claim constant count varies with claim width and stacked arity, and
/// zero-column claims split runs at constraint-group granularity), so the
/// schedule ships as trusted-setup data and the contract walks it.
fn round_run_schedule(
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    starts: &[usize],
) -> Vec<Vec<[usize; 2]>> {
    let end_of = |r: usize| starts.get(r + 1).copied().unwrap_or(program.len());
    starts
        .iter()
        .enumerate()
        .map(|(r, &start)| {
            let mut runs: Vec<[usize; 2]> = Vec::new();
            for i in start..end_of(r) {
                let is_obs = matches!(
                    program[i],
                    SemEvent::ObserveBase { .. } | SemEvent::ObserveBytes { .. }
                );
                let words = if is_obs {
                    fixed[i].as_ref().map_or(0, std::vec::Vec::len)
                } else {
                    0
                };
                // Constant run: fixed observation. Varying run: any other
                // event (proof observation, sample, witness, uniform draw) -
                // each contributes one transcript interaction; word counts
                // for those are the payload sizes the codec defines.
                let kind = usize::from(is_obs && fixed[i].is_some());
                let w = if kind == 1 { words } else { 1 };
                if let Some(last) = runs.last_mut() {
                    if last[0] == kind {
                        last[1] += w;
                        continue;
                    }
                }
                runs.push([kind, w]);
            }
            runs
        })
        .collect()
}

/// Shared export tail, in memory: classification outputs + framing tables +
/// semantic blob, returned as `(vectors doc, blob)`.
///
/// This is the whole export computation with no filesystem attached - the node
/// calls it to build a WBND bundle straight from a block artifact, while the
/// test-side [`export_and_write`] stays a thin writer over the same code. One
/// implementation, so the committed vectors and the node's bundle cannot
/// drift. `statement` (canonical limbs) is embedded only when provided - the
/// block export ships the statement ShieldedPool.applyBlock must pass
/// alongside the proof.
pub fn build_vectors_doc(
    doc: serde_json::Value,
    out: &ReplayOut,
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    starts: &[usize],
    statement: Option<&[F]>,
    extras: Vec<(&str, serde_json::Value)>,
) -> Result<(serde_json::Value, Vec<u8>), Box<dyn Error>> {
    let varying = varying_positions(program, fixed);
    let blob = replay_blob(program, fixed).expect("composed blob");
    let mut doc = doc;
    doc["varying_positions"] = json!(varying);
    let const_words = round_const_words(program, fixed, starts);
    doc["round_const_words"] = json!(const_words);
    doc["round_fixed_runs"] = json!(round_fixed_runs(program, fixed, starts));
    doc["round_run_schedule"] = json!(round_run_schedule(program, fixed, starts));
    let claim_schedules: Vec<Vec<Vec<[usize; 2]>>> = doc["rounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rd| {
            let po = rd["walk"]["phase_offsets"].as_array().unwrap();
            let all: Vec<usize> = po.iter().map(|v| v.as_u64().unwrap() as usize).collect();
            let claims = rd["walk"]["claim_widths"].as_array().unwrap().len();
            let n = (claims + 1).min(all.len());
            let offsets = &all[..n];
            claim_run_schedule(program, fixed, offsets)
        })
        .collect();
    doc["claim_run_schedules"] = json!(&claim_schedules);
    doc["round_framing_tables"] = json!(round_framing_tables(
        &doc,
        program,
        fixed,
        starts,
        &claim_schedules,
    ));
    doc["blob_len"] = json!(blob.len());
    if let Some(pis) = statement {
        doc["statement"] = json!(pis
            .iter()
            .map(p3_field::PrimeField32::as_canonical_u32)
            .collect::<Vec<_>>());
    }
    for (k, v) in extras {
        doc[k] = v;
    }
    doc["phase_marks_before_delegate"] = json!(out
        .phase_marks
        .iter()
        .find(|(n, _)| n == "before_delegate")
        .map(|(_, at)| *at));
    Ok((doc, blob))
}

/// Shared export tail: classification outputs + framing tables + blob written to
/// `contracts/test/vectors/{name}.json` / `{name}.bin`. `statement` (canonical
/// limbs) is embedded only when provided - the block export ships the statement
/// ShieldedPool.applyBlock must pass alongside the proof.
pub fn export_and_write(
    doc: serde_json::Value,
    out: &ReplayOut,
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    starts: &[usize],
    name: &str,
    statement: Option<&[F]>,
    extras: Vec<(&str, serde_json::Value)>,
) -> Result<(), Box<dyn Error>> {
    let (doc, blob) = build_vectors_doc(doc, out, program, fixed, starts, statement, extras)?;
    let const_words = doc["round_const_words"].as_array().map_or(0, Vec::len);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    std::fs::create_dir_all(&dir).expect("vectors dir");
    std::fs::write(
        dir.join(format!("{name}.json")),
        serde_json::to_string_pretty(&doc).expect("serialize"),
    )
    .expect("write json");
    std::fs::write(dir.join(format!("{name}.bin")), &blob).expect("write bin");
    println!(
        "wrote {name}.json: {} rounds, program {} events, blob {} bytes, {} fixed runs, const words {:?}",
        doc["num_rounds"].as_u64().unwrap(),
        doc["program_len"].as_u64().unwrap(),
        blob.len(),
        fixed.iter().filter(|f| f.is_some()).count(),
        const_words,
    );
    Ok(())
}

/// Consumption-aligned framing schedules for every composed round.
///
/// Each entry is `{hex, pre_claims, claim_framings, batching, seps}`: the
/// framing bytes of one round's region plus the word counts at the four points
/// the contract consumes them - before the claims, once per claim, at the
/// batching draw, and once per sumcheck separator. See `round_framing_table`
/// for which fixed events count as framing.
fn round_framing_tables(
    doc: &serde_json::Value,
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    starts: &[usize],
    claim_schedules: &[Vec<Vec<[usize; 2]>>],
) -> Vec<serde_json::Value> {
    doc["rounds"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(r, rd)| {
            let po = rd["walk"]["phase_offsets"].as_array().unwrap();
            let all: Vec<usize> = po.iter().map(|v| v.as_u64().unwrap() as usize).collect();
            let claims = rd["walk"]["claim_widths"].as_array().unwrap().len();
            let claim_offsets = &all[..(claims + 1).min(all.len())];
            let st = starts[r];
            let en = starts.get(r + 1).copied().unwrap_or(program.len());
            let widths: Vec<usize> = rd["walk"]["claim_widths"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as usize)
                .collect();
            let ft = round_framing_table(program, fixed, st, en, claim_offsets, &widths);
            // Cross-check: the per-claim framings must match the claim run
            // schedules' leading constant-run lengths (the contract consumes
            // both views and they must agree).
            let claim_framing: Vec<usize> = claim_schedules[r]
                .iter()
                .zip(widths.iter())
                .map(|(runs, w)| {
                    let region: usize = runs.iter().map(|run| run[1]).sum();
                    region - 4 * w
                })
                .collect();
            assert_eq!(
                claim_framing, ft.claim_framings,
                "round {r}: framing-table claim totals disagree with claim run schedules"
            );
            let _ = claims;
            json!({
                "hex": ft.hex,
                "pre_claims": ft.pre_claims,
                "claim_framings": ft.claim_framings,
                "batching": ft.batching,
                "seps": ft.seps,
            })
        })
        .collect()
}

/// The node-facing bundle: prove a settlement batch and encode the WBND v4
/// bundle the contract consumes, entirely in memory.
///
/// This is the same pipeline the block export test runs
/// (`composed_program_equality_and_export`), minus the filesystem: two
/// composed runs (the first only to classify constant runs against the
/// second), the framing tables via [`build_vectors_doc`], then
/// [`crate::wbnd::flat_from_vectors`] + [`crate::wbnd::encode_bundle`].
/// The bundle embeds the proof of the SECOND run - the same run whose
/// transcript events the blob carries - so what the contract verifies is
/// exactly what the blob encodes; the caller's already-verified artifact
/// proof is a different random run and is not shipped.
///
/// Returns the bundle bytes plus the vectors doc (the audit surface:
/// statement limbs, constraint identity, framing tables) so the operator
/// can pin or archive it.
///
/// Cost note (D-092 batch 89): one settlement proof per call. With settlement
/// blinding off the classification no longer needs a second observation - the
/// fixed/varying split is structural (see `structural_batch_fixed`).
pub fn settlement_bundle(
    rc: &RecursionCircuit,
    statement: &[F],
) -> Result<(Vec<u8>, serde_json::Value), Box<dyn Error>> {
    let (bundle, jj, _blob) = settlement_bundle_with_blob(rc, statement, 1)?;
    Ok((bundle, jj))
}

/// The composed bundle triple: (WBND bundle, vectors doc, semantic blob).
pub type SettlementBundle = (Vec<u8>, serde_json::Value, Vec<u8>);

/// [`settlement_bundle`] plus the semantic blob, so a test can seed the
/// Solidity transcript the way the composed harness does (the blob is the
/// third bundle input and otherwise only lives inside the WBND frame).
pub fn settlement_bundle_with_blob(
    rc: &RecursionCircuit,
    statement: &[F],
    rate: usize,
) -> Result<SettlementBundle, Box<dyn Error>> {
    // D-092 batch 45: WHIR_POW_FLOOR (if set) is applied inside
    // settlement_params_for, so prover and replay configs stay identical.
    // Batch 64 experiment: WHIR_FINAL_LDE overrides the settlement LDE.
    let lde: usize = std::env::var("WHIR_FINAL_LDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::block::BLOCK_LOG_MAX_LDE);
    let params = settlement_params_for(lde, rate);
    // D-092 batch 89: settlement blinding is off, so two production runs are
    // byte-identical and a same-run diff classifies nothing. The delegate-region
    // split comes from a seed-twin pair instead: the same settlement proven
    // twice under two Fiat-Shamir initial states, so every witness-dependent
    // value moves while keccak framing labels stay put (see twin_delegate_fixed).
    // The batch region stays structural. The bundle ships seed 0's proof.
    let (doc, out, program, fixed, starts) =
        composed_run_twin(statement, rc, &params, lde, rate)?;
    let (jj, blob) = build_vectors_doc(
        doc,
        &out,
        &program,
        &fixed,
        &starts,
        Some(statement),
        Vec::new(),
    )?;
    let flat = crate::wbnd::flat_from_vectors(&jj);
    let bundle = crate::wbnd::encode_bundle(&flat, &jj, &blob);
    Ok((bundle, jj, blob))
}
