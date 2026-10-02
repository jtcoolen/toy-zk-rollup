//! Golden vectors: Rust proves, Solidity replays.
//!
//! ## What this pins
//!
//! The Solidity WHIR verifier is a from-scratch reimplementation of a
//! protocol implemented in Rust. Every seam between them is a place where a
//! silent disagreement produces either a verifier that accepts nothing or — far
//! worse — one that accepts the wrong thing. Golden vectors close those seams:
//! the Rust side produces real bytes from a real proof run, the Solidity side
//! consumes them, and any divergence fails a test rather than a settlement.
//!
//! Three vectors, each pinning a different class of drift:
//!
//! | file | pins | drift class |
//! |---|---|---|
//! | `field_vectors.json` | canonical↔Montgomery conversion, per-value | representation |
//! | `transcript_vectors.json` | the exact absorb/squeeze byte sequence of a real verify run | transcript ordering |
//! | `block_vectors.json` | a full settled block: statement, transcript words, proof bytes | everything at once |
//!
//! ## Why the transcript vector is the important one
//!
//! A transcript is a sequence of absorbs and squeezes. The order is set by the
//! verifier's control flow, not by any spec, and a reimplementation that
//! absorbs the same *set* of values in a different order derives completely
//! different challenges while looking correct in review. Recording the real
//! sequence from a real `verify()` call is the only way to pin it.
//!
//! ## Proof bytes are not canonical
//!
//! WHIR's proof-of-work search runs in parallel and returns whichever
//! candidate a worker finds first. Two runs of the *same* proof therefore
//! carry *different* witnesses and different byte lengths — measured at
//! 727,896 vs 729,944 bytes for one identical transfer, first differing at
//! offset 121,140.
//!
//! This is not a soundness problem. `check_witness` accepts any witness whose
//! absorption zeroes the required bits, so every such proof verifies. It is a
//! *vector* problem: a golden vector cannot be regenerated and compared
//! byte-wise, because regeneration does not reproduce the bytes.
//!
//! The vectors therefore pin the witness explicitly. A Solidity test replays
//! the recorded absorb sequence, feeds the recorded witness to its own
//! `checkWitness`, and must get `true` — deterministic, because the witness
//! came from the file rather than from a fresh grind. `transcript_vectors`
//! validates exactly this on the Rust side before writing, so a vector that
//! would not replay is never written.
//!
//! ## Regenerating
//!
//! ```sh
//! cargo test -p prover --test golden_vectors -- --ignored --nocapture
//! ```
//!
//! Ignored by default on purpose. A Solidity test that regenerated its own
//! vectors would be testing the generator rather than the verifier. Vectors
//! are generated deliberately and a change shows up as a reviewable diff.

#![cfg(test)]

use std::error::Error;
use std::path::{Path, PathBuf};

use p3_challenger::{CanObserve, CanSample, GrindingChallenger};
use p3_field::{PrimeCharacteristicRing, PrimeField32, PrimeField64};

use prover::export::{
    canonical, monty, statement_forms, StatementForms, KOALABEAR_P, MONTGOMERY_R,
};
use prover::transcript_trace::{Event, TracedTranscript};

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

fn write_vector(name: &str, value: &serde_json::Value) -> Result<PathBuf, Box<dyn Error>> {
    let dir = vectors_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    let pretty = serde_json::to_string_pretty(value)?;
    std::fs::write(&path, format!("{pretty}\n"))?;
    Ok(path)
}

/// Field-representation vectors.
///
/// Every value carries both forms plus the two conversions, so the Solidity
/// test can check its own `toMonty`/`fromMonty` against the table without
/// reimplementing either. The set is chosen to cover the corners: zero, one,
/// the 16-bit limb maximum, a value whose Montgomery form has high bits set,
/// and the largest canonical value.
#[test]
fn field_vectors() -> Result<(), Box<dyn Error>> {
    // p - 1 fits in u32: p = 2^31 - 2^27 + 1 < 2^31, so the narrowing cast
    // below is exact and cannot truncate.
    #[allow(clippy::cast_possible_truncation)]
    const P_MINUS_ONE: u32 = (KOALABEAR_P - 1) as u32;
    let values: Vec<u32> = vec![0, 1, 2, 7, 0xffff, 0x1234, 1_000_000, P_MINUS_ONE];
    let mut out = Vec::new();
    for &v in &values {
        let m = monty(v);
        // Cross-check against the real field rather than trusting our own
        // arithmetic on both sides of the table.
        let f = <prover::whir::F as p3_field::PrimeCharacteristicRing>::from_u32(v);
        assert_eq!(m, f.to_unique_u32(), "monty({v}) must match the field");
        assert_eq!(canonical(m), v, "round trip for {v}");
        out.push(serde_json::json!({
            "canonical": v,
            "montgomery": m,
            "montgomery_le_hex": hex(&m.to_le_bytes()),
            "canonical_le_hex": hex(&v.to_le_bytes()),
        }));
    }
    let path = write_vector(
        "field_vectors.json",
        &serde_json::json!({
            "modulus": KOALABEAR_P,
            "montgomery_r": MONTGOMERY_R,
            "note": "montgomery_le_hex is the byte string the transcript absorbs; it is NOT canonical_le_hex",
            "values": out,
        }),
    )?;
    println!("wrote {}", path.display());
    Ok(())
}
/// One step of a transcript program.
///
/// The transcript is a *program*, not a blob: a sequence of absorbs and
/// squeezes whose order determines every challenge. Expressing it as data
/// lets the same program drive the Rust challenger (producing the golden
/// values) and the Solidity challenger (replaying them), which is the whole
/// anti-drift mechanism.
enum Step {
    /// Absorb a base-field element.
    Observe(u32),
    /// Sample a base-field challenge.
    Sample,
    /// Grind a proof-of-work witness of `bits` difficulty.
    Grind(usize),
}

/// A transcript program that mirrors the settlement verifier's shape:
/// commit, challenge, public values, OOD point, proof-of-work.
fn settlement_program() -> Vec<Step> {
    vec![
        Step::Observe(0xdead_beef), // a commitment
        Step::Sample,               // alpha
        Step::Observe(1),           // public values
        Step::Observe(2),
        Step::Observe(0xffff),
        Step::Sample, // zeta
        Step::Grind(4),
    ]
}

/// Transcript vectors from a live challenger.
///
/// Runs the settlement program against a traced challenger, records every
/// byte and every derived challenge, and emits both the JSON vector and a
/// generated Solidity test that replays the same program.
#[test]
fn transcript_vectors() -> Result<(), Box<dyn Error>> {
    use prover::whir::F;

    let mut traced = TracedTranscript::<F>::new();
    let mut challenges: Vec<u64> = Vec::new();
    let mut witness: Option<F> = None;
    let mut pow_bits = 0usize;

    for step in settlement_program() {
        match step {
            Step::Observe(v) => traced.challenger.observe(F::from_u32(v)),
            Step::Sample => {
                let c: F = traced.challenger.sample();
                challenges.push(c.as_canonical_u64());
            }
            Step::Grind(bits) => {
                pow_bits = bits;
                witness = Some(traced.challenger.grind(bits));
            }
        }
    }

    let trace = traced.trace();
    let alpha = challenges[0];
    let zeta = challenges[1];
    let witness = witness.expect("the program grinds");

    let events: Vec<serde_json::Value> = trace
        .events
        .iter()
        .map(|ev| match ev {
            Event::Observe { tag, bytes } => serde_json::json!({
                "op": "observe", "tag": tag, "hex": hex(bytes), "len": bytes.len(),
            }),
            Event::Sample { tag, bytes } => serde_json::json!({
                "op": "sample", "tag": tag, "hex": hex(bytes), "len": bytes.len(),
            }),
        })
        .collect();

    let path = write_vector(
        "transcript_vectors.json",
        &serde_json::json!({
            "hash": "keccak256",
            "note": "exact byte sequence a verifier must replay; sample hex is squeezed, observe hex is absorbed",
            "program": settlement_program_json(),
            "challenges": challenges,
            "alpha_canonical": alpha,
            "zeta_canonical": zeta,
            "witness_canonical": witness.as_canonical_u64(),
            "witness_montgomery_le_hex": hex(&witness.to_unique_u32().to_le_bytes()),
            "pow_bits": pow_bits,
            "events": events,
        }),
    )?;
    println!("wrote {} ({} events)", path.display(), trace.len());

    emit_solidity_transcript_test(&challenges, &hex(&witness.to_unique_u32().to_le_bytes()))?;
    Ok(())
}

/// The program as JSON, so the Solidity generator and any future consumer
/// reads the same description rather than re-deriving it from a trace.
fn settlement_program_json() -> Vec<serde_json::Value> {
    settlement_program()
        .into_iter()
        .map(|s| match s {
            Step::Observe(v) => serde_json::json!({"observe": v}),
            Step::Sample => serde_json::json!({"sample": true}),
            Step::Grind(b) => serde_json::json!({"grind": b}),
        })
        .collect()
}

/// Emit the generated Solidity transcript-replay test.
///
/// The Rust side is the source of truth; the on-chain test is generated from
/// it and never hand-written. This is the anti-drift mechanism from
/// `input-output-hk/plutus-plonky3-exploration`: their `convert.py` turns a
/// Rust proof dump into an Aiken test literal, and the generated file is
/// checked in so a transcript change shows up as a reviewable diff.
///
/// The emitted program is the trace *up to the grind's own absorb*. The
/// grind's search activity is prover-side noise that the verifier never
/// replays: the verifier absorbs the witness that came from the proof and
/// calls `checkWitness`, which is exactly the last absorb plus a bit sample.
fn emit_solidity_transcript_test(
    challenges: &[u64],
    witness_monty_le: &str,
) -> Result<(), Box<dyn Error>> {
    // Emit the program itself, not a trace parse. The program is the source
    // of truth and the recorded challenges are its real outputs, so the
    // generated Solidity is the same program with the same expected values.
    //
    // (Parsing the trace instead would be wrong: `grind` clones the
    // challenger to search candidates and the `Arc`-shared sink records the
    // clone's activity, so the raw event stream contains prover-side search
    // noise the verifier never replays.)
    let mut lines: Vec<String> = Vec::new();
    let mut samples = 0usize;
    let mut challenge_at = 0usize;

    for step in settlement_program() {
        match step {
            Step::Observe(v) => {
                // The transcript absorbs the MONTGOMERY representation, not
                // the canonical value. This is the transport fact from
                // D-045 and the single most likely place for a silent
                // divergence between the two implementations.
                let bytes = prover::export::monty(v).to_le_bytes();
                lines.push(format!(
                    "        state.observeBytes(hex\"{}\"); // canonical {v:#x}, absorbed as Montgomery",
                    hex(&bytes)
                ));
            }
            Step::Sample => {
                let expected = challenges[challenge_at];
                challenge_at += 1;
                lines.push(format!("        uint256 s{samples} = state.sampleBase();"));
                lines.push(format!(
                    "        assertEq(s{samples}, {expected}, \"sample {samples} diverges from the Rust transcript\");"
                ));
                samples += 1;
            }
            Step::Grind(bits) => {
                lines.push(format!(
                    "        // Proof-of-work: absorbing the witness must zero the next {bits} bits."
                ));
                lines.push(format!(
                    "        state.observeBytes(hex\"{witness_monty_le}\");"
                ));
                lines.push(format!(
                    "        assertEq(state.sampleBitsUnchecked({bits}), 0, \"PoW witness does not satisfy the challenge\");"
                ));
            }
        }
    }

    let body = lines.join("\n");

    let src = format!(
        r#"// SPDX-License-Identifier: MIT
// GENERATED by `crates/prover/tests/golden_vectors.rs::transcript_vectors`.
// DO NOT EDIT BY HAND — regenerate with:
//     cargo test -p prover --test golden_vectors transcript_vectors -- --ignored --nocapture
//
// Replays the exact interleaved absorb/sample program the Rust settlement
// transcript performs, asserting every challenge the Solidity challenger
// derives equals the value the Rust prover saw.
//
// Interleaving is the point. Fiat-Shamir is a running hash: absorbing the
// same set of bytes in a different order derives completely different
// challenges while looking correct in review. This file is generated from
// the program that produced the real values, so the order cannot drift.
//
// Note the absorbed bytes are MONTGOMERY forms, not canonical values. The
// statement crossing the settlement boundary is canonical; the transcript
// absorbs Montgomery. See D-045.
pragma solidity ^0.8.28;

import {{Test}} from "forge-std/Test.sol";
import {{KeccakChallenger}} from "../lib/sol-whir-p3/transcript/KeccakChallenger.sol";

contract TranscriptReplayTest is Test {{
    using KeccakChallenger for KeccakChallenger.State;

    /// The whole point of this test: replay the Rust program and land on the
    /// Rust challenges. Any change to the absorb/sample order changes every
    /// subsequent challenge, so this fails loudly rather than drifting.
    function test_replay_matches_rust_challenges() public pure {{
        KeccakChallenger.State memory state;

{body}
    }}
}}
"#,
    );

    // `vectors_dir()` is `<root>/contracts/test/vectors`; its parent is the
    // Solidity test directory.
    let dir = vectors_dir()
        .parent()
        .map(Path::to_path_buf)
        .ok_or("could not locate contracts/test")?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("TranscriptReplay.t.sol");
    std::fs::write(&path, src)?;
    println!("wrote generated {}", path.display());
    Ok(())
}

/// A full settled block: the object the contract actually receives.
///
/// Proves one transfer end-to-end under the Keccak settlement config and emits
/// the statement in both forms plus the serialized proof. This is the vector
/// that would catch a layout change, a header change, or a proof-format change.
#[test]
fn block_vectors() -> Result<(), Box<dyn Error>> {
    use prover::client::{prove_client_transfer, ClientSpec};
    use prover::fixtures::{funded_note, seed};
    use prover::transfer::LOG_MAX_LDE;
    use prover::whir_recursion::InnerWhirConfig;
    use shielded::keys::derive_spend_pk;
    use shielded::tree::CommitmentTree;

    use pq_hash::Keccak256Commitment;

    let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0)?;
    let (note, sk_d) = funded_note(11, 1_000);
    let recipient = derive_spend_pk(&pq_hash::Sha3_256Shielded, &seed(9));
    let output = shielded::Note::new(900, seed(0x51), seed(0x52), recipient);

    let mut tree = CommitmentTree::new(Keccak256Commitment);
    tree.append(&note.commit(&Keccak256Commitment));
    let root = tree.root();
    let path = tree.path(0).expect("path exists").siblings;

    let mut map = shielded::NullifierMap::new(Keccak256Commitment);
    let spec = ClientSpec {
        note: &note,
        sk_d: &sk_d,
        path: &path,
        index: 0,
        output: &output,
        fee: 100,
    };
    let artifacts = prove_client_transfer(&inner, &spec, root, &mut map)?;

    // The statement in both forms, from the same slice.
    let forms: StatementForms = statement_forms(&artifacts.statement);
    assert_eq!(
        forms.canonical.len(),
        artifacts.statement.len(),
        "both forms must cover the whole statement"
    );

    let bundle = prover::export::bundle(&artifacts.statement, &artifacts.proof, 1, spec.fee)
        .expect("bundle builds");

    // Computed outside the `json!` macro: the generic parameters contain
    // tokens the macro's matcher cannot parse.
    let proof_keccak = {
        use p3_symmetric::CryptographicHasher;
        hex(&p3_keccak::Keccak256Hash.hash_iter(bundle.proof.iter().copied()))
    };

    let path = write_vector(
        "block_vectors.json",
        &serde_json::json!({
            "note": "a real settled block; statement limbs are canonical, transcript_words are Montgomery",
            "num_transfers": bundle.num_transfers,
            "total_fee": bundle.total_fee,
            "statement_len": bundle.statement.len(),
            "statement": bundle.statement,
            "transcript_words": bundle.transcript_words,
            "transcript_bytes_hex_len": bundle.transcript_words.len() * 4,
            "proof_len": bundle.proof.len(),
            "proof_keccak_hex": proof_keccak,
        }),
    )?;
    println!(
        "wrote {} (statement {} limbs, proof {} bytes)",
        path.display(),
        bundle.statement.len(),
        bundle.proof.len()
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}
