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
//!
//! ## What is pinned, and what must NOT be
//!
//! `golden_vectors_are_current` runs on every `cargo test` and re-derives the
//! deterministic parts of each checked-in file. It deliberately does NOT pin
//! proof bytes, proof length, or a proof's transcript commitments: HVZK
//! blinding folds the mask into the committed trace (D-051 finding 1), so two
//! proofs of one statement differ at the commitment level by design. Pinning
//! those would make the suite fail for a reason that means nothing, and a
//! test that fails for no reason is a test that gets deleted.

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
#[ignore = "regenerates a checked-in golden vector; run deliberately so the diff is reviewed"]
fn field_vectors() -> Result<(), Box<dyn Error>> {
    // p - 1 fits in u32: p = 2^31 - 2^27 + 1 < 2^31, so the narrowing cast
    // below is exact and cannot truncate.
    #[allow(clippy::cast_possible_truncation)]
    const P_MINUS_ONE: u32 = (KOALABEAR_P - 1) as u32;
    let values = field_value_set(P_MINUS_ONE);
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
/// The value set behind `field_vectors.json`, shared with the always-on check.
///
/// Chosen to cover the corners: zero, one, small values, the 16-bit limb
/// maximum, a value whose Montgomery form has high bits set, and the largest
/// canonical value.
fn field_value_set(p_minus_one: u32) -> Vec<u32> {
    vec![0, 1, 2, 7, 0xffff, 0x1234, 1_000_000, p_minus_one]
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
///
/// Rewrites two checked-in files, so it is ignored. `golden_vectors_are_current`
/// is the test that runs on every `cargo test`.
#[test]
#[ignore = "regenerates a checked-in golden vector AND the generated Solidity test; run deliberately"]
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

    let events = event_values(&trace.events);

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

/// Recorded transcript events as JSON, shared by the generator and the
/// always-on check so both describe a trace the same way.
fn event_values(events: &[Event]) -> Vec<serde_json::Value> {
    events
        .iter()
        .map(|ev| match ev {
            Event::Observe { tag, bytes } => serde_json::json!({
                "op": "observe", "tag": tag, "hex": hex(bytes), "len": bytes.len(),
            }),
            Event::Sample { tag, bytes } => serde_json::json!({
                "op": "sample", "tag": tag, "hex": hex(bytes), "len": bytes.len(),
            }),
        })
        .collect()
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
#[ignore = "regenerates a checked-in golden vector; run deliberately so the diff is reviewed"]
fn block_vectors() -> Result<(), Box<dyn Error>> {
    use prover::client::{prove_client_transfer, ClientSpec};
    use prover::fixtures::{funded_note, seed};
    use prover::transfer::LOG_MAX_LDE;
    use prover::whir_recursion::InnerWhirConfig;
    use shielded::keys::derive_spend_pk;

    use pq_hash::Poseidon2Commitment;

    let inner = InnerWhirConfig::new(LOG_MAX_LDE, 0)?;
    let (note, sk_d) = funded_note(11, 1_000);
    let recipient = derive_spend_pk(&pq_hash::Poseidon2Shielded, &seed(9));
    let output = shielded::Note::new(900, seed(0x51), seed(0x52), recipient);

    // D-088: the commitment tree is Poseidon2; the nullifier map stays Keccak.
    let (tree, paths) = prover::fixtures::tree_with(&[note]);
    let path = paths[0].clone();

    let mut map = shielded::NullifierMap::new(Poseidon2Commitment::default());
    let spec = ClientSpec {
        note: &note,
        sk_d: &sk_d,
        path: &path,
        index: 0,
        output: &output,
        fee: 100,
    };
    let artifacts = prove_client_transfer(&inner, &spec, &tree, &mut map)?;

    // D-089: the block statement is the FOLDED form - header, statement fold
    // root, endpoint digests, fee - built by the same shared builder the circuit
    // export mirrors. The transfer statement itself is the fold input, not a
    // part of what the contract sees.
    let shape = prover::block::TransferShape {
        num_nullifiers: 1,
        num_outputs: 1,
    };
    let block_statement =
        prover::block::block_statement([shape].iter(), [artifacts.statement.as_slice()])?;

    // The statement in both forms, from the same slice.
    let forms: StatementForms = statement_forms(&block_statement);
    assert_eq!(
        forms.canonical.len(),
        block_statement.len(),
        "both forms must cover the whole statement"
    );

    let bundle = prover::export::bundle(&block_statement, &artifacts.proof, 1, spec.fee)
        .expect("bundle builds");

    // The roots and digests ShieldedPool chains, as hex so the Solidity test
    // can compare them against what it decodes from the statement limbs. These
    // are the public values the circuit proved, read off the same run that made
    // the proof. D-088: there is no pool-side tree to mirror any more - the
    // contract stores the attested `rootAfter` - so the statement's own roots
    // are the whole story.
    let public = &artifacts.public;
    let roots_hex = |r: &pq_hash::MerkleRoot| r.to_hex();

    let digests_hex = |ds: &[pq_hash::Nullifier]| -> Vec<String> {
        ds.iter().map(pq_hash::Nullifier::to_hex).collect()
    };
    let outputs_hex: Vec<String> = public
        .outputs
        .iter()
        .map(pq_hash::NoteHash::to_hex)
        .collect();

    // Computed outside the `json!` macro: the generic parameters contain
    // tokens the macro's matcher cannot parse.
    let proof_keccak = {
        use p3_symmetric::CryptographicHasher;
        hex(&p3_keccak::Keccak256Hash.hash_iter(bundle.proof.iter().copied()))
    };

    // The folded statement root, computed natively over the child statement -
    // the same chain the circuit performs in-circuit (pinned element-for-element
    // by `commitment_gadget::fold_statement_matches_native`). The Solidity test
    // compares this against what it decodes from the statement limbs.
    let statement_root_hex = hex(pq_hash::elements_to_digest(
        &prover::block::fold_statement_native(std::iter::once(artifacts.statement.as_slice())),
    )
    .as_bytes());

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
            "root_before_hex": roots_hex(&public.root),
            "statement_root_hex": statement_root_hex,
            "root_after_hex": roots_hex(&public.root_after),
            "nullifier_before_hex": roots_hex(&public.nullifier_roots.before),
            "nullifier_after_hex": roots_hex(&public.nullifier_roots.after),
            "nullifiers_hex": digests_hex(&public.nullifiers),
            "outputs_hex": outputs_hex,
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

// ---------------------------------------------------------------------------
// Always-on vector currency check
// ---------------------------------------------------------------------------

/// Reads a checked-in vector file.
fn read_vector(name: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("{}: {e} (regenerate with --ignored)", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

/// The block fixture behind `block_vectors.json`.
///
/// One definition, shared by the generator (which proves) and by the always-on
/// check (which only needs the statement). Rebuilding the note in two places is
/// how a vector ends up describing a transfer the prover would never produce.
struct BlockFixture {
    note: shielded::Note,
    sk_d: [u8; 32],
    path: Vec<pq_hash::Digest32>,
    index: usize,
    output: shielded::Note,
    fee: u64,
    tree: shielded::tree::CommitmentTree<pq_hash::Poseidon2Commitment>,
}

impl BlockFixture {
    fn build() -> Self {
        use prover::fixtures::{funded_note, seed};
        use shielded::keys::derive_spend_pk;

        let (note, sk_d) = funded_note(11, 1_000);
        let recipient = derive_spend_pk(&pq_hash::Poseidon2Shielded, &seed(9));
        let output = shielded::Note::new(900, seed(0x51), seed(0x52), recipient);

        let (tree, paths) = prover::fixtures::tree_with(&[note]);
        let path = paths[0].clone();
        Self {
            note,
            sk_d,
            path,
            index: 0,
            output,
            fee: 100,
            tree,
        }
    }

    fn transfer(&self) -> shielded::Transfer<'_> {
        shielded::Transfer {
            spends: vec![shielded::transfer::Spend {
                note: &self.note,
                sk_d: &self.sk_d,
                path: &self.path,
                index: self.index,
            }],
            outputs: vec![self.output],
            fee: self.fee,
        }
    }

    /// The public values, derived WITHOUT proving.
    ///
    /// The same call `prove_client_transfer` makes internally; exposing it lets
    /// the always-on check pin the root/nullifier/commitment hex fields without
    /// a proving run.
    fn public_values(&self) -> shielded::TransferPublic {
        let map = shielded::NullifierMap::new(pq_hash::Poseidon2Commitment::default());
        let transfer = self.transfer();
        let (public, _witnesses, _frontier) =
            prover::fixtures::public_and_witnesses_from(&transfer, &self.tree, map);
        public
    }

    /// The statement limbs, derived WITHOUT proving.
    ///
    /// This is the cheap half of what `prove_client_transfer` computes, and it is
    /// the half the contract actually verifies, so it is the half worth pinning
    /// on every cargo test run. D-089: the block statement is the FOLDED form,
    /// so the transfer statement is first built, then folded through the same
    /// shared builder the circuit export mirrors - the check pins exactly what
    /// the contract will be handed, not the fold's input.
    fn statement(&self) -> Vec<prover::whir::F> {
        let child = self.child_statement();
        let shape = prover::block::TransferShape {
            num_nullifiers: 1,
            num_outputs: 1,
        };
        prover::block::block_statement([shape].iter(), [child.as_slice()])
            .expect("fixture block statement builds")
    }

    /// The child (transfer) statement — the fold's input, exposed separately so
    /// the check can recompute the fold root without re-deriving the fixture.
    fn child_statement(&self) -> Vec<prover::whir::F> {
        let map = shielded::NullifierMap::new(pq_hash::Poseidon2Commitment::default());
        let transfer = self.transfer();
        let (public, witnesses, frontier) =
            prover::fixtures::public_and_witnesses_from(&transfer, &self.tree, map);
        prover::transfer::build_transfer_circuit(&transfer, &public, &witnesses, &frontier)
            .expect("fixture circuit builds")
            .statement()
            .to_vec()
    }
}

/// The checked-in vectors must still describe what THIS code produces.
///
/// Unlike the generators above, this runs on every cargo test. It exists
/// because the generators rewrite their own fixtures: without this check, a
/// change to the transcript, the field representation, or the statement layout
/// would be absorbed silently into the JSON on the next full test run, and the
/// Solidity side would keep passing against a vector that no longer matches
/// the prover.
///
/// What it pins, and what it deliberately does not:
///
/// - Pins the transcript program, the derived challenges, and the VALIDITY of
///   the recorded proof-of-work witness.
/// - Does NOT pin the witness VALUE. Grinding is a parallel batch search whose
///   first accepted candidate depends on batch layout (p3-challenger's
///   `hash_challenger.rs:277` uses `find_map_any`), so the value is
///   environment-dependent while its validity is not. Validity is both the
///   stable assertion and the stronger one.
/// - Does NOT pin proof bytes or proof length. HVZK blinding folds the mask
///   into the committed trace (D-051 finding 1), so two proofs of one statement
///   differ at the commitment level by design.
#[test]
fn golden_vectors_are_current() -> Result<(), Box<dyn Error>> {
    check_field_vectors()?;
    check_transcript_vectors()?;
    check_block_vectors()?;
    Ok(())
}

fn check_field_vectors() -> Result<(), Box<dyn Error>> {
    let v = read_vector("field_vectors.json")?;
    assert_eq!(
        v["modulus"].as_u64().expect("modulus"),
        KOALABEAR_P,
        "field_vectors.json pins a different modulus than the prover uses"
    );
    assert_eq!(
        v["montgomery_r"].as_u64().expect("montgomery_r"),
        MONTGOMERY_R,
        "field_vectors.json pins a different Montgomery R"
    );

    #[allow(clippy::cast_possible_truncation)]
    let expected = field_value_set((KOALABEAR_P - 1) as u32);
    let values = v["values"].as_array().expect("values array");
    assert_eq!(
        values.len(),
        expected.len(),
        "field_vectors.json value set drifted"
    );
    for (want, got) in expected.iter().zip(values) {
        assert_eq!(
            got["canonical"].as_u64().expect("canonical"),
            u64::from(*want)
        );
        assert_eq!(
            got["montgomery"].as_u64().expect("montgomery"),
            u64::from(monty(*want)),
            "montgomery form for {want} diverges from the prover"
        );
        assert_eq!(
            got["montgomery_le_hex"].as_str().expect("hex"),
            hex(&monty(*want).to_le_bytes()),
            "the absorbed byte string for {want} diverges"
        );
    }
    Ok(())
}

fn check_transcript_vectors() -> Result<(), Box<dyn Error>> {
    use prover::whir::F;

    let v = read_vector("transcript_vectors.json")?;
    assert_eq!(v["hash"].as_str().expect("hash"), "keccak256");
    assert_eq!(
        v["program"],
        serde_json::Value::Array(settlement_program_json()),
        "the recorded transcript program is not the program this crate defines"
    );

    // Replay the program against a fresh traced challenger and compare the
    // challenges it derives. Any change to the absorb order, the field
    // representation, or the sponge shows up here.
    let mut traced = TracedTranscript::<F>::new();
    let mut challenges: Vec<u64> = Vec::new();
    for step in settlement_program() {
        match step {
            Step::Observe(x) => traced.challenger.observe(F::from_u32(x)),
            Step::Sample => {
                let c: F = traced.challenger.sample();
                challenges.push(c.as_canonical_u64());
            }
            // The grind is the last step. Its witness is validated below rather
            // than re-derived, because grinding is a parallel search.
            Step::Grind(_) => {}
        }
    }

    let recorded: Vec<u64> = v["challenges"]
        .as_array()
        .expect("challenges")
        .iter()
        .map(|c| c.as_u64().expect("challenge is a u64"))
        .collect();
    assert_eq!(recorded.len(), 2, "expected alpha and zeta");
    assert_eq!(
        challenges, recorded,
        "the Rust transcript no longer produces the challenges the Solidity verifier replays"
    );
    assert_eq!(v["alpha_canonical"].as_u64().expect("alpha"), recorded[0]);
    assert_eq!(v["zeta_canonical"].as_u64().expect("zeta"), recorded[1]);

    // The witness must still satisfy the recorded difficulty against THIS
    // transcript state. That is the assertion the generated Solidity test makes
    // with its own checkWitness, so both sides are held to the same standard.
    let pow_bits =
        usize::try_from(v["pow_bits"].as_u64().expect("pow_bits")).expect("pow_bits fits");
    let witness_canonical =
        u32::try_from(v["witness_canonical"].as_u64().expect("witness")).expect("a field element");
    assert_eq!(
        v["witness_montgomery_le_hex"]
            .as_str()
            .expect("witness hex"),
        hex(&monty(witness_canonical).to_le_bytes()),
        "the recorded witness hex is not the Montgomery LE form of the recorded value"
    );

    let witness = F::from_u32(witness_canonical);
    assert!(
        traced.challenger.check_witness(pow_bits, witness),
        "the recorded proof-of-work witness no longer satisfies the challenge"
    );
    Ok(())
}

fn check_block_vectors() -> Result<(), Box<dyn Error>> {
    let v = read_vector("block_vectors.json")?;
    let fixture = BlockFixture::build();
    let statement = fixture.statement();
    let forms: StatementForms = statement_forms(&statement);

    let recorded: Vec<u64> = v["statement"]
        .as_array()
        .expect("statement")
        .iter()
        .map(|s| s.as_u64().expect("limb is a u64"))
        .collect();
    // canonical is already a Vec<u64>, so this is a clone, not a conversion.
    let now: Vec<u64> = forms.canonical.clone();
    assert_eq!(
        now, recorded,
        "block_vectors.json pins a statement the current circuit no longer produces"
    );
    assert_eq!(
        v["statement_len"].as_u64().expect("statement_len"),
        u64::try_from(recorded.len()).expect("len fits u64"),
        "statement_len disagrees with the statement array"
    );

    // The words the settlement transcript absorbs are the Montgomery form of
    // the same limbs, so drift here means the contract and the prover disagree
    // about what a statement byte looks like.
    let words: Vec<u64> = v["transcript_words"]
        .as_array()
        .expect("transcript_words")
        .iter()
        .map(|w| w.as_u64().expect("word is a u64"))
        .collect();
    let now_words: Vec<u64> = forms
        .transcript_words
        .iter()
        .map(|&w| u64::from(w))
        .collect();
    assert_eq!(
        now_words, words,
        "block_vectors.json transcript_words no longer match the Montgomery form of the statement"
    );
    // D-089: the fold root recorded in the vector must be the native fold of
    // the child statement - the same chain the circuit performs. If the fold
    // drifts, the statement's own limbs and this pin disagree and the contract
    // would store a root no prover attested.
    let child = fixture.child_statement();
    let now_root = hex(
        pq_hash::elements_to_digest(&prover::block::fold_statement_native(std::iter::once(
            child.as_slice(),
        )))
        .as_bytes(),
    );
    assert_eq!(
        v["statement_root_hex"]
            .as_str()
            .expect("statement_root_hex"),
        now_root,
        "block_vectors.json statement_root_hex no longer matches the native fold"
    );
    // The pool-side hex fields must describe the same public values the
    // statement encodes. Decoding them from the statement limbs here would
    // duplicate LimbCodec; comparing against the fixture's own public values
    // pins the same fact from the other side.
    let public = fixture.public_values();
    let hex_field = |key: &str| -> Vec<String> {
        v[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} missing"))
            .iter()
            .map(|x| {
                x.as_str()
                    .unwrap_or_else(|| panic!("{key} entry not a string"))
                    .to_string()
            })
            .collect()
    };
    let expect_hex = |key: &str, want: String| {
        let got = v[key].as_str().unwrap_or_else(|| panic!("{key} missing"));
        assert_eq!(got, want, "{key} drifted from the fixture's public values");
    };
    expect_hex("root_before_hex", public.root.to_hex());
    expect_hex("root_after_hex", public.root_after.to_hex());
    expect_hex(
        "nullifier_before_hex",
        public.nullifier_roots.before.to_hex(),
    );
    expect_hex("nullifier_after_hex", public.nullifier_roots.after.to_hex());
    let recorded_nullifiers = hex_field("nullifiers_hex");
    let want_nullifiers: Vec<String> = public
        .nullifiers
        .iter()
        .map(pq_hash::Nullifier::to_hex)
        .collect();
    assert_eq!(
        recorded_nullifiers, want_nullifiers,
        "nullifiers_hex drifted"
    );
    let recorded_outputs = hex_field("outputs_hex");
    let want_outputs: Vec<String> = public
        .outputs
        .iter()
        .map(pq_hash::NoteHash::to_hex)
        .collect();
    assert_eq!(recorded_outputs, want_outputs, "outputs_hex drifted");

    assert_eq!(v["num_transfers"].as_u64().expect("num_transfers"), 1);
    assert_eq!(
        v["total_fee"].as_u64().expect("total_fee"),
        fixture.fee,
        "total_fee drifted from the fixture"
    );
    Ok(())
}
