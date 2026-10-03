//! The transcript program as a compact binary blob, for the Solidity side to drive.
//!
//! Why a blob and not JSON: the contract would have to parse thousands of JSON
//! objects, and parsing is where a verifier picks up a bug. Here it walks a byte
//! table. One writer lives here so that every artifact the contract consumes is
//! spelled by the same code; two writers drift, and a drifted schedule is worse
//! than a missing one because the contract follows it happily into a desync.
//!
//! # Layout, header fields big-endian
//!
//! ```text
//! magic "WSPR" | version u16 | schedule_len u16
//!   | const_len u32 | var_len u32 | sample_len u32 | uniform_len u32 | witness_len u32
//! ```
//!
//! Version history: v1 carried ops 0-5. v2 adds [`OP_CONST_COMMITMENT`] (6) and
//! [`OP_UNIFORM_BITS_32`] (7), needed by the batch layer - a trusted-setup commitment and
//! uniform draws wider than 16 bits. A v1 reader would misparse a v2 stream, so the
//! version moved; nothing else about the format changed.
//!
//! then `schedule_len` entries of `[kind u8, arg u8, run u16]`, then the five
//! payloads.
//!
//! The `SAMPLE_BASE` arg is the basis-coefficient count of each logged sample (1
//! for a base-field draw; a quartic extension element is four consecutive runs of
//! it).
//!
//! Field payloads are 4-byte LITTLE-endian words, because that is the order the
//! transcript absorbs them in: a run of constant observations is exactly the byte
//! string the sponge must eat, so the contract absorbs it without re-encoding.
//! Uniform draws are 2-byte BIG-endian words, matching the width the contract
//! reads them at.

use crate::semantic_trace::{SemEvent, SemProgram};
use std::error::Error;

/// Operation kinds in the compact replay blob; one byte each.
///
/// The Solidity verifier dispatches on these, so the numbering is part of the wire
/// format. Changing a number here silently changes what the contract does, so the
/// blob carries a version and the Solidity test asserts it.
pub const OP_CONST_U32: u8 = 0;
/// Observe one base-field word taken from the proof rather than from a constant.
pub const OP_VAR_U32: u8 = 1;
/// Observe a commitment digest: 32 raw bytes from the variable payload.
pub const OP_COMMITMENT: u8 = 2;
/// Sample base-field elements from the sponge and compare against the sample pool.
pub const OP_SAMPLE_BASE: u8 = 3;
/// Draw uniform bits and compare against the uniform pool.
pub const OP_UNIFORM_BITS: u8 = 4;
/// Check a proof-of-work witness at the given difficulty.
pub const OP_CHECK_WITNESS: u8 = 5;
/// Observe a commitment digest taken from the constant payload rather than the proof.
///
/// A commitment is normally proof data, but a trusted-setup commitment - the preprocessed
/// trace commitment of a batch with preprocessed AIRs - commits the same matrices in every
/// proof, so classification finds it fixed. It is not even present in the batch proof, so
/// the contract must carry it as a literal; this op is how it reaches the constant payload.
/// Additive: a stream that never uses it is unaffected.
pub const OP_CONST_COMMITMENT: u8 = 6;
/// Draw uniform bits into a 4-byte big-endian word.
///
/// The 2-byte form cannot hold a draw wider than 16 bits, and WHIR query indices are drawn
/// at the full LDE domain width - 21 bits at `log_max_lde` 22 - so the wide draws get their
/// own op rather than a widened payload that a v1 reader would misparse. Additive: a
/// stream that never draws more than 16 uniform bits is byte-identical to before.
pub const OP_UNIFORM_BITS_32: u8 = 7;

/// Header size in bytes: magic, version, schedule length, five payload lengths.
pub const HEADER_LEN: usize = 28;

/// The blob format version this writer emits, asserted by every reader.
pub const BLOB_VERSION: u16 = 2;

/// Extend a run-length schedule by one operation, merging with the previous entry
/// when the kind and argument match.
pub fn push_run(schedule: &mut Vec<(u8, u8, usize)>, kind: u8, arg: u8) {
    match schedule.last_mut() {
        Some(last) if last.0 == kind && last.1 == arg => last.2 += 1,
        _ => schedule.push((kind, arg, 1)),
    }
}

/// Classify every observation position as config-fixed or proof-dependent.
///
/// Returns one entry per event in `runs[0]` - the value observed there when every
/// run agreed. A position that never moves is fixed by the config, so the contract
/// carries it as a literal; one that moves is proof data read from the calldata.
///
/// Sampled positions are always `None`: a sampled value is proof-dependent by
/// construction, and a witness check consumes a proof field, so classifying those
/// could only ever answer "varies".
///
/// # Panics
///
/// Panics if `runs` is empty.
#[must_use]
pub fn classify_observations(runs: &[SemProgram]) -> (Vec<Option<Vec<u32>>>, Vec<usize>) {
    let value_at = |e: &SemEvent| -> Option<Vec<u32>> {
        match e {
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
    };
    assert!(!runs.is_empty(), "classification needs at least one run");
    let mut varying_positions = Vec::new();
    let fixed_values: Vec<Option<Vec<u32>>> = runs[0]
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let v0 = value_at(e)?;
            let fixed = runs
                .iter()
                .all(|run| value_at(&run[i]).as_deref() == Some(v0.as_slice()));
            if fixed {
                Some(v0)
            } else {
                varying_positions.push(i);
                None
            }
        })
        .collect();
    (fixed_values, varying_positions)
}

/// Encode the program and its fixed-value classification into the blob format.
///
/// # Errors
///
/// When the program contains an event the format cannot carry (a raw
/// `SampleBits`, a grinding record, an oversized run or bit count).
pub fn replay_blob(
    program: &SemProgram,
    fixed: &[Option<Vec<u32>>],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut schedule: Vec<(u8, u8, usize)> = Vec::new();
    let mut constants: Vec<u8> = Vec::new();
    let mut variables: Vec<u8> = Vec::new();
    let mut samples: Vec<u8> = Vec::new();
    let mut uniform: Vec<u8> = Vec::new();
    let mut witnesses: Vec<u8> = Vec::new();

    for (i, event) in program.iter().enumerate() {
        match event {
            SemEvent::ObserveBase { value } => {
                if let Some(v) = &fixed[i] {
                    constants.extend_from_slice(&v[0].to_le_bytes());
                    push_run(&mut schedule, OP_CONST_U32, 0);
                } else {
                    variables.extend_from_slice(&value.to_le_bytes());
                    push_run(&mut schedule, OP_VAR_U32, 0);
                }
            }
            // A commitment is proof data unless every run agreed on it, which happens
            // exactly for trusted-setup commitments. classify_observations split the
            // digest into little-endian words, so writing those words back little-endian
            // reproduces the absorbed bytes exactly.
            SemEvent::ObserveBytes { bytes } => {
                if let Some(words) = &fixed[i] {
                    for w in words {
                        constants.extend_from_slice(&w.to_le_bytes());
                    }
                    push_run(&mut schedule, OP_CONST_COMMITMENT, 4);
                } else {
                    variables.extend_from_slice(bytes);
                    push_run(&mut schedule, OP_COMMITMENT, 4);
                }
            }
            // The recorder logs one event per BASIS COEFFICIENT, so a quartic
            // extension element arrives as four consecutive arity-1 events. The run
            // encoder merges them; the arg is the coefficient count per event.
            SemEvent::SampleBase { values } => {
                for v in values {
                    samples.extend_from_slice(&v.to_le_bytes());
                }
                let arg = u8::try_from(values.len())?;
                push_run(&mut schedule, OP_SAMPLE_BASE, arg);
            }
            SemEvent::SampleUniformBits { bits, value } => {
                let arg = u8::try_from(*bits)?;
                if *bits > 16 {
                    // u32, not usize: usize::to_be_bytes is 8 bytes on 64-bit targets and
                    // would misalign every later read in the payload.
                    uniform.extend_from_slice(&u32::try_from(*value)?.to_be_bytes());
                    push_run(&mut schedule, OP_UNIFORM_BITS_32, arg);
                } else {
                    uniform.extend_from_slice(&u16::try_from(*value)?.to_be_bytes());
                    push_run(&mut schedule, OP_UNIFORM_BITS, arg);
                }
            }
            SemEvent::CheckWitness { bits, witness, ok } => {
                if !ok {
                    return Err(format!("event {i}: a proof-of-work witness failed").into());
                }
                witnesses.extend_from_slice(&witness.to_le_bytes());
                let arg = u8::try_from(*bits)?;
                push_run(&mut schedule, OP_CHECK_WITNESS, arg);
            }
            // Absent in the settlement shape. Reaching either means the protocol
            // changed and the blob format needs new payloads, not a guess.
            SemEvent::SampleBits { bits, .. } => {
                return Err(
                    format!("event {i}: SampleBits({bits}) is not in the blob format").into(),
                );
            }
            SemEvent::Grind { bits, .. } => {
                return Err(format!("event {i}: Grind({bits}) is not in the blob format").into());
            }
        }
    }

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"WSPR");
    out.extend_from_slice(&BLOB_VERSION.to_be_bytes());
    out.extend_from_slice(&u16::try_from(schedule.len())?.to_be_bytes());
    for len in [
        constants.len(),
        variables.len(),
        samples.len(),
        uniform.len(),
        witnesses.len(),
    ] {
        out.extend_from_slice(&u32::try_from(len)?.to_be_bytes());
    }
    for (kind, arg, run) in &schedule {
        out.push(*kind);
        out.push(*arg);
        out.extend_from_slice(&u16::try_from(*run)?.to_be_bytes());
    }
    out.extend_from_slice(&constants);
    out.extend_from_slice(&variables);
    out.extend_from_slice(&samples);
    out.extend_from_slice(&uniform);
    out.extend_from_slice(&witnesses);
    Ok(out)
}
