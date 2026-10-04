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

use p3_field::{PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_multilinear_util::point::Point;
use p3_recursion::pcs::whir::uni::plan::checked_stacked_num_variables;
use p3_recursion::pcs::whir::uni::{padded_arity, univariate_eq_point};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, OpeningRequest, TableShape, TableSpec};
use p3_whir::parameters::WhirConfig;
use serde_json::json;

use prover::semantic_blob::{classify_observations, replay_blob};
use prover::semantic_trace::{SemChallenger, SemEvent, SemProgram};
use prover::whir::FOLDING_FACTOR;
use prover::whir_recursion::{RecursionCircuit, LOG_MAX_LDE};
use prover::F;

mod batch_fixture;
mod whir_walk;
use batch_fixture::{
    base_json, com_json, dom_json, ext_json, fib_recursion, hex, one_run_for, settlement_params,
    settlement_params_for, Challenge, Dft, OpeningClaims, OpeningProof, ReplayOut, SemPcs,
    CAP_HEIGHT,
};
use prover::block::{build_multi_transfer_circuit, shape_header, ChildProof, TransferShape};
use prover::client::{prove_client_transfer, ClientSpec};
use prover::fixtures::{funded_note, seed, tree_with};
use prover::whir_recursion::InnerWhirConfig;
use pq_hash::{Keccak256Commitment, Sha3_256Shielded};
use shielded::keys::derive_spend_pk;
use shielded::{Note, NullifierMap};
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
        "starting_folding_pow_bits": config.starting_folding_pow_bits(),
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
        "initial_sumcheck_pow_witnesses": walk.initial_sumcheck_pow_witnesses.clone(),
        "last_root": hex(&walk.last_root),
        "bound_evals": exts2(&walk.bound_evals),
        "claim_widths": walk.claim_widths,
        "phase_offsets": walk.phase_offsets,
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
    composed_run_with(&pis, &rc, params, LOG_MAX_LDE, rounds_json, round_starts)
}

/// The composed run at an explicit circuit + settlement shape. The Fibonacci
/// recursion circuit and the real shielded block circuit differ in both, but the
/// composition claim is the same: the shared WHIR walk inside the batch delegate
/// reproduces the native PCS's transcript event-for-event.
fn composed_run_with(
    pis: &[F],
    rc: &RecursionCircuit,
    params: p3_whir::parameters::ProtocolParameters,
    log_max_lde: usize,
    rounds_json: &mut Vec<serde_json::Value>,
    round_starts: &mut Vec<usize>,
) -> Result<(serde_json::Value, ReplayOut, SemProgram), Box<dyn Error>> {

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
        let (program, out, _verifier, _proof) =
            one_run_for(pis, rc, Some(&mut replacer), log_max_lde);
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

/// Segment each round region's config-fixed absorbs into runs, exactly as
/// whir_proof_vectors::fixed_runs does for a whole program but scoped to one
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
fn reclassify_zero_runs(
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
/// Per-claim run schedule for one composed round: for each opening claim,
/// the alternating [is_constant, words] runs of its transcript region,
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
                words += fixed[i].as_ref().map_or(1, |v| v.len());
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
/// Returns the concatenated little-endian hex of the kept words and the
/// per-run word counts, so the contract can slice them into its schedule
/// structs by position.
fn round_framing_table(
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    start: usize,
    end: usize,
    phase_offsets: &[usize],
) -> (String, Vec<usize>) {
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
    // Per-claim framing prefix length in events: leading fixed events of the
    // claim before its first varying event.
    let is_fixed_ev = |i: usize| {
        matches!(
            program[i],
            SemEvent::ObserveBase { .. } | SemEvent::ObserveBytes { .. }
        ) && fixed[i].is_some()
    };
    let mut framing_prefix: Vec<usize> = Vec::new();
    for w in phase_offsets.windows(2) {
        let (a, b) = (w[0], w[1]);
        let mut n = 0usize;
        let mut i = a;
        while i < b && is_fixed_ev(i) {
            n += 1;
            i += 1;
        }
        framing_prefix.push(n);
    }
    // Claim index for a position: the c with phase_offsets[c] <= i < offsets[c+1].
    let claim_of = |i: usize| -> Option<usize> {
        for c in 0..framing_prefix.len() {
            if i >= phase_offsets[c] && i < phase_offsets[c + 1] {
                return Some(c);
            }
        }
        None
    };
    let mut bytes: Vec<u8> = Vec::new();
    let mut lens: Vec<usize> = Vec::new();
    let mut seg = 0usize;
    let mut i = start;
    while i < end {
        if !is_fixed_ev(i) {
            if seg > 0 {
                lens.push(seg);
                seg = 0;
            }
            i += 1;
            continue;
        }
        let words = fixed[i].as_ref().map_or(1, |v| v.len());
        let keep = if i < claims_start || i >= last_claim_end {
            true
        } else if let Some(c) = claim_of(i) {
            // Offset within the claim, in events.
            let mut off = 0usize;
            let mut k = phase_offsets[c];
            while k < i {
                off += 1;
                k += 1;
            }
            off < framing_prefix[c]
        } else {
            false
        };
        if keep {
            if let Some(ws) = &fixed[i] {
                for w in ws {
                    bytes.extend(w.to_le_bytes());
                }
            }
            seg += words;
        } else if seg > 0 {
            lens.push(seg);
            seg = 0;
        }
        i += 1;
    }
    if seg > 0 {
        lens.push(seg);
    }
    (hex(&bytes), lens)
}
/// The full alternating run schedule of one round region: every maximal run
/// of constant (fixed) or varying observations as `[is_constant, words]`
/// pairs, in order. This is the contract's walk plan: absorb `words` constant
/// words from the trusted table, then read `words` words of proof data from
/// calldata, alternating. The constant runs' VALUES are in round_fixed_runs;
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
                    fixed[i].as_ref().map_or(0, |w| w.len())
                } else {
                    0
                };
                // Constant run: fixed observation. Varying run: any other
                // event (proof observation, sample, witness, uniform draw) -
                // each contributes one transcript interaction; word counts
                // for those are the payload sizes the codec defines.
                let kind = if is_obs && fixed[i].is_some() { 1 } else { 0 };
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

    let (fixed_raw, varying_raw) = classify_observations(&[program_a.clone(), program_b.clone()]);
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
    export_and_write(doc, &out, &program_b, &fixed, &starts_b, "composed_vectors", None, vec![])
        .expect("export");
}

/// Shared export tail: classification outputs + framing tables + blob written to
/// `contracts/test/vectors/{name}.json` / `{name}.bin`. `statement` (canonical
/// limbs) is embedded only when provided - the block export ships the statement
/// ShieldedPool.applyBlock must pass alongside the proof.
fn export_and_write(
    doc: serde_json::Value,
    out: &ReplayOut,
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
    starts: &[usize],
    name: &str,
    statement: Option<&[F]>,
    extras: Vec<(&str, serde_json::Value)>,
) -> Result<(), Box<dyn Error>> {
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
        doc["statement"] = json!(pis.iter().map(|v| v.as_canonical_u32()).collect::<Vec<_>>());
    }
    for (k, v) in extras {
        doc[k] = v;
    }
    doc["phase_marks_before_delegate"] = json!(out
        .phase_marks
        .iter()
        .find(|(n, _)| n == "before_delegate")
        .map(|(_, at)| *at));

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
            let (hexbytes, lens) = round_framing_table(program, fixed, st, en, claim_offsets);
            // The per-claim framings are the claim run schedules' leading
            // constant-run lengths; they appear contiguously in `lens`.
            let claim_framing: Vec<usize> = claim_schedules[r]
                .iter()
                .map(|runs| {
                    runs.first()
                        .map_or(0, |run| if run[0] == 1 { run[1] } else { 0 })
                })
                .collect();
            let mut p = 0usize;
            'find: while p + claim_framing.len() <= lens.len() {
                for k in 0..claim_framing.len() {
                    if lens[p + k] != claim_framing[k] {
                        p += 1;
                        continue 'find;
                    }
                }
                break;
            }
            // One framing block per virtual claim (OOD sample): the runs
            // before the first concrete claim interleave with the virtual
            // claims' point draws, so they must stay separate.
            let pre_claims: Vec<usize> = lens[..p].to_vec();
            let batching = lens[p + claim_framing.len()];
            let seps = lens[p + claim_framing.len() + 1..].to_vec();
            json!({
                "hex": hexbytes,
                "pre_claims": pre_claims,
                "claim_framings": claim_framing,
                "batching": batching,
                "seps": seps,
            })
        })
        .collect()
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


/// The real shielded block circuit through the same composed machinery.
///
/// One client transfer (a funded note spent through the transfer circuit with a
/// real SPHINCS+ signature, SHA3-256 note derivation and nullifier absence fold)
/// recursed into the block circuit and settled under the Keccak WHIR config at
/// BLOCK_LOG_MAX_LDE. The export is what the contract replays:
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
    let root = tree.root();
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
    let client = prove_client_transfer(&inner, &spec, root, &mut map).expect("client prove");

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
        params.clone(),
        prover::block::BLOCK_LOG_MAX_LDE,
        &mut rounds_a,
        &mut starts_a,
    )?;

    let mut rounds_b = Vec::new();
    let mut starts_b = Vec::new();
    let (doc, out, program_b) = composed_run_with(
        &pis,
        &rc,
        params,
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
    // Genesis data for the on-chain test: the pool must start at the tree the
    // block was witnessed against (the funded note's leaf), and the expected
    // root after the block's output is appended pins the contract's own
    // accumulator against the prover's tree.
    let mut pool_tree = tree_with(&[note]).0;
    pool_tree.append(&out_note.commit(&Keccak256Commitment));
    let extras = vec![
        (
            "genesis_leaves",
            json!([hex(note.commit(&Keccak256Commitment).as_bytes())]),
        ),
        ("pool_root_after_hex", json!(hex(pool_tree.root().as_bytes()))),
    ];
    // Small sidecar for the Solidity test: the full export is tens of MB and
    // parsing it on-chain in setUp exhausts the EVM memory limit. The E2E test
    // reads only this file plus the bundle.
    let sidecar = serde_json::json!({
        "statement": pis.iter().map(|v| v.as_canonical_u32()).collect::<Vec<_>>(),
        "genesis_leaves": extras
            .iter()
            .find(|(k, _)| *k == "genesis_leaves")
            .map(|(_, v)| v.clone())
            .unwrap(),
        "pool_root_after_hex": extras
            .iter()
            .find(|(k, _)| *k == "pool_root_after_hex")
            .map(|(_, v)| v.clone())
            .unwrap(),
    });
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    std::fs::write(
        dir.join("block_genesis.json"),
        serde_json::to_string_pretty(&sidecar)?,
    )?;
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
