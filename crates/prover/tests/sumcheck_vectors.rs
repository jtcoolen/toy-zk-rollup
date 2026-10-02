//! Golden vectors for the WHIR sumcheck round fold.
//!
//! WHY THIS FILE EXISTS
//!
//! The vendored `sol-whir-p3` verifier folds each sumcheck round with
//! `KoalaBearExt4.extrapolate_012` — Lagrange interpolation of a
//! quadratic through the nodes **{0, 1, 2}**. Our prover does not use that
//! identity. p3 0.8.0's WHIR verifier
//! (`p3_whir::pcs::verifier::mod`, all three call sites) calls
//! `SumcheckData::verify_rounds(..., Basis::Evaluation)`, whose round
//! identity is `extrapolate_01inf` — interpolation through
//! **{0, 1, infinity}**:
//!
//! ```text
//!     h(r) = h(0) * (1 - r) + h(1) * r + h(inf) * r * (r - 1)
//! ```
//!
//! with the round invariant `h(0) + h(1) = C` supplying `h(1) = C - h(0)`,
//! so the fold the verifier actually performs is
//!
//! ```text
//!     C' = c_a * (1 - r) + (C - c_a) * r + c_inf * r * (r - 1)
//! ```
//!
//! These are different functions of the same three inputs. Both return a
//! well-formed field element and neither panics. A verifier built by
//! copying the vendored fold would accept proofs our prover never made and
//! reject proofs it did, and nothing in the byte layout would reveal it.
//!
//! HOW THESE VECTORS ARE PRODUCED
//!
//! Not by reimplementing the fold. The real `SumcheckData::verify_rounds`
//! is driven through the workspace's traced Keccak challenger, so the
//! recorded wire bytes are exactly the bytes the real verifier absorbs, in
//! the real order, and the folded claim is the real verifier's output. The
//! Solidity side is therefore checked against the identity and the
//! transcript the prover uses, not against a transcription of them.
//!
//! Regenerate with:
//!     cargo test -p prover --test `sumcheck_vectors` -- --ignored --nocapture

use std::error::Error;
use std::path::{Path, PathBuf};

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_sumcheck::lagrange::extrapolate_01inf;
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::SumcheckData;
use prover::transcript_trace::{Event, TracedTranscript};
use prover::whir::{Challenge as EF, F};

/// Where checked-in vectors live, relative to the workspace root.
fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(
            || PathBuf::from("contracts/test/vectors"),
            |root| root.join("contracts/test/vectors"),
        )
}

/// Canonical limbs of an extension element; index 0 is the constant term.
///
/// Explicitly canonical: p3 serializes `MontyField31` in Montgomery form
/// because it is faster, so a serde dump would carry Montgomery limbs.
/// The Solidity library works in canonical limbs.
fn limbs(v: &EF) -> Vec<u64> {
    <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(v)
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect()
}

fn ext(t: (u64, u64, u64, u64)) -> EF {
    EF::new([
        F::from_u64(t.0),
        F::from_u64(t.1),
        F::from_u64(t.2),
        F::from_u64(t.3),
    ])
}

/// Operands chosen to stress the fold: zero, one, `p - 1`, and values whose
/// products overflow a single 31-bit limb so the reduction is exercised.
const P: u64 = 2_130_706_433;
const OPERANDS: [(u64, u64, u64, u64); 8] = [
    (0, 0, 0, 0),
    (1, 0, 0, 0),
    (0, 1, 0, 0),
    (P - 1, 0, 0, 0),
    (7, 11, 13, 17),
    (1_234_567_890 % P, 987_654_321 % P, 429_496_729 % P, 777),
    (0x7f00_0000 % P, 0x3fff_ffff, 1, 0x0f0f_0f0f),
    (42, 0, 0, P - 1),
];

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// The domain-separator prefix: everything absorbed before the first round.
///
/// Rendered as one contiguous hex string so the Solidity side can absorb
/// it verbatim instead of reconstructing the `InteractionPattern`. The
/// prefix is deterministic for a fixed shape, so this is a constant the
/// generated fixed config can carry.
fn prefix_hex(wire: &[String], num_rounds: usize) -> String {
    let observes: Vec<&str> = wire
        .iter()
        .filter(|e| e.starts_with("observe "))
        .map(|e| e.split('_').nth(1).unwrap_or(""))
        .collect();
    let prefix = &observes[..observes.len() - 8 * num_rounds];
    prefix.concat()
}

/// The per-round absorbed bytes, round by round, as hex strings.
fn round_absorbs_hex(wire: &[String], num_rounds: usize) -> Vec<String> {
    let observes: Vec<&str> = wire
        .iter()
        .filter(|e| e.starts_with("observe "))
        .map(|e| e.split('_').nth(1).unwrap_or(""))
        .collect();
    let split = observes.len() - 8 * num_rounds;
    (0..num_rounds)
        .map(|i| observes[split + 8 * i..split + 8 * (i + 1)].concat())
        .collect()
}

/// What one replay of the real verifier produced.
struct Replay {
    /// The folding challenges, one per round.
    challenges: Vec<serde_json::Value>,
    /// The claim after every round was folded.
    final_claim: Vec<u64>,
    /// Every transcript event, in order, rendered as a string.
    wire: Vec<String>,
}

/// Drive the real `verify_rounds` and capture what it absorbed and produced.
fn replay(
    rounds: &[(usize, usize)],
    initial_claim: (u64, u64, u64, u64),
) -> Result<Replay, Box<dyn Error>> {
    let mut data: SumcheckData<F, EF> = SumcheckData::default();
    let mut traced = TracedTranscript::<F>::new();
    let mut claim: EF = ext(initial_claim);

    for &(a, b) in rounds {
        data.polynomial_evaluations
            .push([ext(OPERANDS[a]), ext(OPERANDS[b])]);
    }

    // pow_bits = 0: the witness vector stays empty, which is the canonical
    // shape the verifier enforces. Positive difficulty is covered by the
    // grind vectors in the transcript suite.
    let point = data.verify_rounds(
        &mut traced.challenger,
        &mut claim,
        rounds.len(),
        0,
        Basis::Evaluation,
    )?;

    let challenges: Vec<serde_json::Value> = point
        .as_slice()
        .iter()
        .map(|r| serde_json::json!({ "r": limbs(r) }))
        .collect();

    // The wire: every byte the real verifier absorbed, in order.
    let trace = traced.trace();
    let wire: Vec<String> = trace
        .events
        .iter()
        .map(|e| match e {
            Event::Observe { tag, bytes } => {
                format!("observe {}{}", tag.as_deref().unwrap_or("_"), hex(bytes))
            }
            Event::Sample { tag, bytes } => {
                format!("sample {}{}", tag.as_deref().unwrap_or("_"), hex(bytes))
            }
        })
        .collect();

    Ok(Replay {
        challenges,
        final_claim: limbs(&claim),
        wire,
    })
}

#[test]
#[ignore = "regenerates checked-in contract vectors"]
fn emit_sumcheck_vectors() -> Result<(), Box<dyn Error>> {
    // Deterministic pseudo-random walk over the operand set. A full 4-way
    // cross product would be 4096 cases; a walk with coprime strides visits
    // a wide set of (c_a, c_inf, claimed, r) combinations without
    // bloating the checked-in file.
    let mut cases: Vec<serde_json::Value> = Vec::new();
    let mut idx = [0usize; 4];
    for _ in 0..256 {
        let c_a = ext(OPERANDS[idx[0]]);
        let c_inf = ext(OPERANDS[idx[1]]);
        let claimed = ext(OPERANDS[idx[2]]);
        let r = ext(OPERANDS[idx[3]]);

        // The exact fold the verifier performs, from the real library.
        let folded = extrapolate_01inf(c_a, claimed - c_a, c_inf, r);

        cases.push(serde_json::json!({
            "c_a": limbs(&c_a),
            "c_inf": limbs(&c_inf),
            "claimed_sum": limbs(&claimed),
            "r": limbs(&r),
            "folded": limbs(&folded),
        }));

        idx[0] = (idx[0] + 1) % OPERANDS.len();
        idx[1] = (idx[1] + 3) % OPERANDS.len();
        idx[2] = (idx[2] + 5) % OPERANDS.len();
        idx[3] = (idx[3] + 7) % OPERANDS.len();
    }

    // Multi-round replays through the real verifier entry point, at the
    // round counts our schedule actually uses.
    let mut replays: Vec<serde_json::Value> = Vec::new();
    for &n_rounds in &[1usize, 4, 5] {
        let rounds: Vec<(usize, usize)> = (0..n_rounds).map(|i| (i % 8, (i * 3 + 1) % 8)).collect();
        let r2 = replay(&rounds, (1, 2, 3, 4))?;
        replays.push(serde_json::json!({
            "num_rounds": n_rounds,
            "initial_claim": limbs(&ext((1, 2, 3, 4))),
            "inputs": rounds
                .iter()
                .map(|&(a, b)| {
                    serde_json::json!({
                        "c_a": limbs(&ext(OPERANDS[a])),
                        "c_inf": limbs(&ext(OPERANDS[b])),
                    })
                })
                .collect::<Vec<_>>(),
            "challenges": r2.challenges,
            "final_claim": r2.final_claim,
            "wire": r2.wire,
            "prefix_hex": prefix_hex(&r2.wire, n_rounds),
            "round_absorbs_hex": round_absorbs_hex(&r2.wire, n_rounds),
        }));
    }

    let dir = vectors_dir();
    std::fs::create_dir_all(&dir)?;
    let out = dir.join("sumcheck_vectors.json");
    let json = serde_json::json!({
        "hash": "keccak256",
        "field": "KoalaBear",
        "extension_degree": 4,
        "basis": "Evaluation",
        "note": "Round fold is extrapolate_01inf over {0,1,infinity}: \
                C' = c_a*(1-r) + (C - c_a)*r + c_inf*r*(r-1). \
                NOT extrapolate_012 over {0,1,2}. Replays are produced by \
                the real SumcheckData::verify_rounds over the traced Keccak \
                challenger.",
        "num_cases": cases.len(),
        "cases": cases,
        "num_replays": replays.len(),
        "replays": replays,
    });
    std::fs::write(&out, serde_json::to_string_pretty(&json)?)?;
    println!("wrote {} ({} cases)", out.display(), cases.len());
    Ok(())
}

/// The domain separator is a deterministic function of the shape, so for a
/// fixed schedule it is a constant the Solidity side can embed. Verify that
/// by replaying the same shape twice and comparing the prefix byte-for-byte.
#[test]
#[ignore = "regenerates checked-in contract vectors"]
fn domain_separator_is_a_constant_per_shape() {
    for &n in &[1usize, 4, 5] {
        let rounds: Vec<(usize, usize)> = (0..n).map(|i| (i % 8, (i * 3 + 1) % 8)).collect();
        let a = replay(&rounds, (1, 2, 3, 4)).expect("replay a");
        let b = replay(&rounds, (1, 2, 3, 4)).expect("replay b");
        let pa = &a.wire[..a.wire.len() - 8 * n];
        let pb = &b.wire[..b.wire.len() - 8 * n];
        assert_eq!(pa, pb, "prefix must be deterministic for a fixed shape");
        println!("n={n} prefix stable, {} events", pa.len());
    }
}
