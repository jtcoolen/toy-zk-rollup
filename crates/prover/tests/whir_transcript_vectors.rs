//! The WHIR verifier's Fiat-Shamir program, recorded from a real verify and replayed.
//!
//! # The gap this closes
//!
//! p3-whir 0.8.0 does not run a bare sponge. It drives a `WhirVerifierTranscript`
//! over a `DomainSeparator`: a versioned, named, labelled transcript in the
//! Spongefish style (IETF draft-irtf-cfrg-fiat-shamir). The seed is
//!
//!     [protocol_id(64) | pattern_hash(32) | label_len_be(4) | label | 0x80]
//!
//! packed three bytes per field element behind a length element, and every later
//! step absorbs a label before its payload.
//!
//! None of that is written down anywhere a verifier author can read. It is upstream
//! control flow. A Solidity verifier that absorbs the same SET of values in a
//! different order, or that skips the seed, derives completely different challenges
//! while looking entirely correct in review — and a verifier that accepts a false
//! proof is the whole ballgame for a rollup.
//!
//! # Method: record, do not reimplement
//!
//! So the program is not transcribed from a reading of the source and declared
//! correct. It is RECORDED from the real verifier's own absorbs and squeezes, and
//! both the Rust and the Solidity side are then checked against that recording. This
//! is the method `GOATNetwork/bitcoin-stark-verifier` uses, and their reasoning is
//! the reason it is the right one: "every other test compares a script against a
//! Rust reference, which establishes that the two agree — not that either is right."
//!
//! Recording also corrects reading. The seed decoded from the first run says
//! version 1, name "p3-uni-stark" — not the version 3, name "p3-whir" that reading
//! the p3-whir source suggests, because uni-stark wraps WHIR as a sub-transcript and
//! the outer transcript is the uni-stark one. A verifier written from the source
//! reading would have absorbed the wrong protocol id and rejected every honest
//! proof, or worse, been tested only against itself.
//!
//! # Why the proof is produced untraced and verified traced
//!
//! The proof comes from the PRODUCTION config. The TRACED config then verifies it.
//! If splicing the recorder into the challenger changed the transcript by even one
//! byte, the challenges would desynchronise and verification would fail. So a green
//! run is itself the evidence that recording did not perturb the protocol. Recording
//! the prover instead would not carry that guarantee: a prover and a verifier can
//! disagree in ways a prover-only run never notices.
//!
//! The proof crosses between the two configs through postcard. `Proof<SC>` is keyed
//! on SC, and SC names the challenger type, so they are distinct Rust types — while
//! the bytes are identical, because the recorder changes no byte on the wire. The
//! round trip is both the type bridge and a free check that the wire format is
//! config-agnostic, which is what the chain relies on.
//!
//! # What is pinned, and why replay rather than regenerate
//!
//! WHIR's proof-of-work is a parallel search that returns whichever candidate a
//! worker finds first, so two runs of one statement carry different witnesses and
//! different byte lengths. The recorded stream therefore cannot be reproduced by
//! re-proving, and a check that re-proved and diffed would be flaky by construction
//! (D-052).
//!
//! Replay sidesteps that and is the stronger check anyway: the vector is fed back
//! through a fresh sponge, every absorb is re-absorbed, and every recorded squeeze
//! must equal what the sponge now produces. That establishes the stream is a genuine
//! transcript rather than a plausible-looking dump, and does so deterministically.
//! The Solidity test does the identical replay on the vendored Keccak sponge. Rust
//! agrees with the vector, Solidity agrees with the vector, therefore Solidity
//! agrees with Rust — with neither side serving as the other's reference.

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_recursion::pcs::whir::uni::WhirUniPcs;
use p3_sumcheck::layout::PrefixProver;
use p3_uni_stark::StarkConfig;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use std::error::Error;
use std::path::{Path, PathBuf};

use prover::config::{mmcs, Mmcs, F};
use prover::transcript_trace::{Event, TraceChallenger, TraceSink, TranscriptTrace};
use prover::whir::{config, required_pow_bits, Challenge, Dft, ZK_ARITY_SLACK};

/// Challenger with the byte recorder spliced in UNDER the serializer.
///
/// The seam matters. `SerializingChallenger32` is the field/byte boundary, so a
/// recorder below it sees raw bytes and never re-implements the serialisation it is
/// meant to be checking. A recorder above it would be a second implementation of the
/// very thing under test.
type TracedChallenger =
    SerializingChallenger32<F, TraceChallenger<HashChallenger<u8, Keccak256Hash, 32>>>;
type TracedPcs = WhirUniPcs<Challenge, F, Dft, Mmcs, TracedChallenger, PrefixProver<F, Challenge>>;
type TracedConfig = StarkConfig<TracedPcs, Challenge, TracedChallenger>;

/// Statement arity for the recorded run.
///
/// 16 is the smallest arity the settlement config is built at in production tests,
/// and it is large enough that WHIR runs a real schedule: several folding rounds,
/// grinding, and a final phase. A smaller arity collapses the schedule and would
/// record fewer steps than the chain ever has to replay.
const NUM_VARIABLES: usize = 16;
/// Trace height. 1024 rows is the measured settlement floor: below it the final
/// phase asks for more queries than the folded domain has positions.
const LOG_ROWS: usize = 10;

/// Modulus of `KoalaBear`, `2^31 - 2^27 + 1`.
const P: u64 = 2_130_706_433;
/// Inverse of `R = 2^32 mod P`, for turning a stored Montgomery value back into a
/// canonical one. The transcript absorbs Montgomery form; the seed layout is only
/// readable in canonical form.
const R_INV: u64 = 1_057_030_144;

/// Protocol parameters mirroring `prover::whir::config`.
///
/// Written out rather than shared through a helper so the traced config differs from
/// the production one in exactly one type parameter and nothing else. A shared
/// builder would hide whether the two agree.
fn params() -> ProtocolParameters {
    let pow_bits = required_pow_bits(NUM_VARIABLES + ZK_ARITY_SLACK).expect("grinding budget");
    ProtocolParameters {
        security_level: prover::whir::SECURITY_LEVEL,
        pow_bits,
        round_log_inv_rates: Vec::new(),
        folding_factor: FoldingFactor::Constant(prover::whir::FOLDING_FACTOR),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}

fn traced_challenger(sink: &TraceSink) -> TracedChallenger {
    SerializingChallenger32::new(TraceChallenger::new(
        HashChallenger::new(Vec::new(), Keccak256Hash {}),
        sink.clone(),
    ))
}

/// The production config with only the challenger type swapped, plus its sink.
fn traced_config() -> (TracedConfig, TraceSink) {
    let sink = TraceSink::new();
    let pcs = TracedPcs::new(
        params(),
        Dft::default(),
        mmcs(prover::whir_recursion::CAP_HEIGHT),
        traced_challenger(&sink),
        NUM_VARIABLES,
    );
    (StarkConfig::new(pcs, traced_challenger(&sink)), sink)
}

/// Width-2 Fibonacci AIR, the shape the throughput harness uses.
#[derive(Clone, Copy, Debug)]
struct FibAir;

impl<F> p3_air::BaseAir<F> for FibAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: p3_air::AirBuilder> p3_air::Air<AB> for FibAir {
    fn eval(&self, builder: &mut AB) {
        use p3_air::{AirBuilder as _, WindowAccess as _};
        let main = builder.main();
        let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
        let (a_next, b_next) = (main.next_slice()[0], main.next_slice()[1]);
        let two = AB::F::ONE + AB::F::ONE;
        let public: AB::Expr = builder.public_values()[0].into();
        builder.when_first_row().assert_eq(a, AB::F::ONE);
        builder.when_first_row().assert_eq(b, AB::F::ONE);
        builder.when_transition().assert_eq(a + b, a_next);
        builder.when_transition().assert_eq(a + b * two, b_next);
        builder.when_last_row().assert_eq(a, public);
    }
}

fn fib(len: usize) -> (p3_matrix::dense::RowMajorMatrix<F>, Vec<F>) {
    let mut values = vec![F::ONE; len * 2];
    for i in 1..len {
        let a = values[(i - 1) * 2];
        let b = values[(i - 1) * 2 + 1];
        values[i * 2] = a + b;
        values[i * 2 + 1] = a + (b + b);
    }
    let last_a = values[values.len() - 2];
    (
        p3_matrix::dense::RowMajorMatrix::new(values, 2),
        vec![last_a],
    )
}

/// Records the verifier's transcript for one real WHIR proof.
fn record() -> Result<TranscriptTrace, Box<dyn Error>> {
    let air = FibAir;
    let (trace, pis) = fib(1 << LOG_ROWS);

    let production = config(prover::whir_recursion::CAP_HEIGHT, NUM_VARIABLES)?;
    let proof =
        p3_uni_stark::prove(&production, &air, trace, &pis).map_err(Box::<dyn Error>::from)?;

    // Cross the config boundary through the settlement wire format. Same bytes,
    // different Rust type — see the module docs.
    let bytes = postcard::to_allocvec(&proof).expect("encode");
    let traced_proof: p3_uni_stark::Proof<TracedConfig> =
        postcard::from_bytes(&bytes).expect("decode into the traced config type");

    let (traced, sink) = traced_config();
    p3_uni_stark::verify(&traced, &air, &traced_proof, &pis).map_err(Box::<dyn Error>::from)?;

    Ok(sink.trace())
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("contracts")
        .join("test")
        .join("vectors")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut out, "{b:02x}").expect("writing to a String never fails");
    }
    out
}

/// Bytes of the little-endian length prefix on each event.
///
/// Four, not two. A two-byte length would silently truncate any absorb over
/// 65535 bytes, and a truncated length desynchronises every later event: the
/// decoder would read payload bytes as headers and produce garbage that still
/// parses. Four bytes removes the limit rather than adding a check for it, and the
/// cost is one byte per event against a stream of a few thousand.
const LEN_BYTES: usize = 4;

/// Self-delimiting encoding of the whole program: one byte of op, four bytes of
/// little-endian length, then the payload.
///
/// A flat hex blob rather than a JSON array of objects because the stream runs to
/// thousands of events. One string keeps the vector to tens of kilobytes, and the
/// Solidity side walks it with a cursor instead of parsing JSON per event.
fn encode(events: &[Event]) -> String {
    let mut out = String::new();
    for ev in events {
        let (op, bytes) = match ev {
            Event::Observe { bytes, .. } => (0u8, bytes),
            Event::Sample { bytes, .. } => (1u8, bytes),
        };
        out.push_str(&hex(&[op]));
        // Explicit u32. `usize::to_le_bytes` is EIGHT bytes on a 64-bit host,
        // which would silently disagree with the four-byte header the decoder
        // reads and desynchronise every event after the first.
        let len = u32::try_from(bytes.len()).expect("an event fits u32");
        out.push_str(&hex(&len.to_le_bytes()));
        out.push_str(&hex(bytes));
    }
    out
}

/// Decodes what `encode` produced. Shared by the generator and the always-on checks
/// so the two cannot disagree about the format.
fn decode(program: &str) -> Result<Vec<(u8, Vec<u8>)>, String> {
    if !program.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    let raw = (0..program.len() / 2)
        .map(|i| {
            u8::from_str_radix(&program[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("bad hex at {i}: {e}"))
        })
        .collect::<Result<Vec<u8>, String>>()?;
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        if i + 1 + LEN_BYTES > raw.len() {
            return Err("truncated event header".into());
        }
        let op = raw[i];
        let mut len_bytes = [0u8; LEN_BYTES];
        len_bytes.copy_from_slice(&raw[i + 1..i + 1 + LEN_BYTES]);
        let len = usize::try_from(u32::from_le_bytes(len_bytes))
            .map_err(|_| "event length exceeds usize".to_string())?;
        i += 1 + LEN_BYTES;
        if i + len > raw.len() {
            return Err("truncated event payload".into());
        }
        out.push((op, raw[i..i + len].to_vec()));
        i += len;
    }
    Ok(out)
}

/// The raw byte sponge the settlement transcript runs on.
///
/// This is the challenger the recorder sits under, so it is the challenger that
/// actually decides the challenge bytes. Replaying through it rather than through
/// the serialising wrapper matters twice over: the recorded events are byte-level
/// absorbs, so they only feed a byte challenger; and it is the same object the
/// Solidity side models, so the replay checks the thing the chain has to reproduce
/// rather than a layer above it.
type ByteSponge = HashChallenger<u8, Keccak256Hash, 32>;

const fn fresh_sponge() -> ByteSponge {
    HashChallenger::new(Vec::new(), Keccak256Hash {})
}

/// Feeds the recorded absorbs into a fresh sponge and asserts every recorded squeeze
/// comes out again, byte for byte.
///
/// This is what makes the vector trustworthy. A dump of plausible-looking bytes
/// fails here immediately: squeeze bytes reproduce only if the absorbs before them
/// are the same absorbs, in the same order, against the same sponge state.
///
/// Returns the number of squeezed bytes checked.
fn replay(events: &[(u8, Vec<u8>)]) -> Result<usize, String> {
    use p3_challenger::{CanObserve, CanSample};
    let mut sponge = fresh_sponge();
    let mut squeezed = 0usize;
    for (i, (op, bytes)) in events.iter().enumerate() {
        match op {
            0 => sponge.observe_slice(bytes),
            1 => {
                let got: Vec<u8> = (0..bytes.len()).map(|_| sponge.sample()).collect();
                if got != *bytes {
                    return Err(format!(
                        "event {i}: recorded {}, replay produced {}",
                        hex(bytes),
                        hex(&got)
                    ));
                }
                squeezed += bytes.len();
            }
            other => return Err(format!("event {i}: unknown op {other}")),
        }
    }
    Ok(squeezed)
}
/// Reads the checked-in vector and decodes its program.
fn load() -> (serde_json::Value, Vec<(u8, Vec<u8>)>) {
    let path = vectors_dir().join("whir_transcript_vectors.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
    let events = decode(v["program"].as_str().expect("program")).expect("decodable program");
    (v, events)
}

/// The vector is a genuine transcript: replaying its absorbs reproduces its
/// squeezes. Runs on every `cargo test`; regenerates nothing.
#[test]
fn whir_transcript_replays() -> Result<(), Box<dyn Error>> {
    let (v, events) = load();

    let declared =
        usize::try_from(v["events"].as_u64().expect("events")).expect("event count fits");
    assert_eq!(
        events.len(),
        declared,
        "the recorded event count and the encoded stream disagree"
    );

    // The seed is the first thing absorbed and it is what separates a labelled
    // transcript from a bare sponge. Replay is self-consistent either way, so the
    // presence of the seed has to be asserted rather than inferred.
    let seed_bytes: usize = events
        .iter()
        .take_while(|(op, _)| *op == 0)
        .map(|(_, b)| b.len())
        .sum();
    assert!(
        seed_bytes >= 64,
        "a labelled transcript opens by absorbing at least the 64-byte protocol id; only {seed_bytes} bytes precede the first squeeze"
    );

    let squeezed = replay(&events).map_err(Box::<dyn Error>::from)?;
    assert!(
        squeezed > 0,
        "the recorded program squeezed nothing, so the replay proves nothing"
    );
    println!(
        "replayed {} events ({} squeezed bytes)",
        events.len(),
        squeezed
    );
    Ok(())
}

/// The seed decodes to the layout `DomainSeparator::seed_bytes` specifies.
///
/// This is the assertion that reading the source got WRONG. p3-whir own separator
/// is version 3, name "p3-whir"; the transcript a settlement proof actually
/// replays is uni-stark one, version 1, name "p3-uni-stark", with WHIR running as
/// a sub-transcript inside it. Hardcoding what the p3-whir source says would have
/// bound the on-chain transcript to the wrong protocol id, and every honest proof
/// would then be rejected — or the verifier would be tested only against itself.
///
/// Checking the decoded STRUCTURE rather than a raw hex blob means a change
/// upstream shows up as "the version byte moved" instead of thousands of mismatched
/// squeeze bytes with no diagnosis.
#[test]
fn whir_transcript_seed_has_the_domain_separator_layout() {
    // Width of the [version | name | zero padding | name_len] protocol id, used
    // throughout the assertions below.
    const PROTOCOL_ID_LEN: usize = 64;

    let (_v, events) = load();

    // Leading absorbs, concatenated: the seed, and nothing else.
    let mut stream: Vec<u8> = Vec::new();
    for (op, b) in &events {
        if *op != 0 {
            break;
        }
        stream.extend_from_slice(b);
    }
    assert!(
        stream.len().is_multiple_of(4),
        "field elements are absorbed 4 bytes at a time; {} is not a whole number of elements",
        stream.len()
    );

    // The absorbed u32s are Montgomery form: stored = canonical * R mod P with
    // R = 2^32, so canonical = stored * R_INV mod P. Plain integer arithmetic, no
    // field import needed. Every canonical value is below P < 2^31, so u32 holds
    // all of them and no later step needs a lossy cast.
    let elements: Vec<u32> = stream
        .as_chunks::<4>()
        .0
        .iter()
        .map(|g| {
            let stored = u64::from(u32::from_le_bytes(*g));
            u32::try_from((stored * R_INV) % P).expect("a canonical value is below P")
        })
        .collect();

    // FieldUnit packing: the first element is the byte length of the payload, then
    // each element carries THREE bytes little-endian — one byte short of the
    // modulus width, so no chunk can reach P and the packing never wraps.
    let payload_len = usize::try_from(*elements.first().expect("the seed absorbs an element"))
        .expect("a payload length fits usize");
    let mut seed: Vec<u8> = Vec::new();
    for e in &elements[1..] {
        seed.extend_from_slice(&e.to_le_bytes()[..3]);
        if seed.len() >= payload_len {
            break;
        }
    }
    assert!(
        seed.len() >= payload_len,
        "the absorbed elements hold {} seed bytes, fewer than the declared {payload_len}",
        seed.len()
    );
    seed.truncate(payload_len);

    // [version | name | zero padding | name_len] is 64 bytes, then the 32-byte
    // pattern hash, then a 4-byte big-endian label length, the label, and 0x80.
    assert!(
        seed.len() > PROTOCOL_ID_LEN + 32 + 4,
        "seed is {} bytes, too short to hold a protocol id, a pattern hash and a length prefix",
        seed.len()
    );
    let name_len = usize::from(seed[PROTOCOL_ID_LEN - 1]);
    assert!(
        name_len > 0,
        "a zero-length protocol name would give no domain separation"
    );
    let name = String::from_utf8_lossy(&seed[1..=name_len]).into_owned();
    assert!(
        // Dash and underscore are the only punctuation a protocol name uses, and
        // the assertion is about printability, not about a specific name.
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == 0x2d || b == 0x5f),
        "protocol name {name:?} is not printable ASCII"
    );
    assert!(
        seed[1 + name_len..PROTOCOL_ID_LEN - 1]
            .iter()
            .all(|&b| b == 0),
        "the bytes between the name and the length byte must be zero padding"
    );

    let label_off = PROTOCOL_ID_LEN + 32;
    let label_len = usize::try_from(u32::from_be_bytes([
        seed[label_off],
        seed[label_off + 1],
        seed[label_off + 2],
        seed[label_off + 3],
    ]))
    .expect("label length fits usize");
    assert_eq!(
        seed.len(),
        label_off + 4 + label_len + 1,
        "the seed must be exactly [id | pattern_hash | len_be | label | terminator]"
    );
    assert_eq!(
        seed[seed.len() - 1],
        0x80,
        "the seeding stream ends with the domain tag"
    );

    println!(
        "seed: version {}, name {name:?}, pattern_hash {}, label {} bytes, terminator 0x80",
        seed[0],
        hex(&seed[PROTOCOL_ID_LEN..label_off]),
        label_len
    );
}

/// A corrupted absorb must break the replay.
///
/// Without this, a replay that silently ignored the absorbs would pass: the squeeze
/// check alone cannot tell "the stream is a real transcript" from "the sponge was
/// never touched". Flipping one seed byte has to change every derived challenge, and
/// this asserts that it does.
#[test]
fn whir_transcript_replay_detects_a_corrupted_seed() {
    let (_v, mut events) = load();

    // Flip the low bit of the first absorbed byte: part of the length element that
    // opens the seed, the most load-bearing byte in the stream.
    let first = events
        .iter_mut()
        .find(|(op, _)| *op == 0)
        .expect("the program absorbs something");
    assert!(!first.1.is_empty(), "an empty absorb cannot be corrupted");
    first.1[0] ^= 1;

    let err = replay(&events).expect_err("a corrupted seed must break the replay");
    println!("corrupted seed rejected as expected: {err}");
}

/// Dropping one absorb must break the replay too.
///
/// The test above changes a byte; this one changes the SHAPE. A verifier that forgot
/// a step — say, never absorbing a round commitment — is the realistic bug, and the
/// same vector has to catch it.
#[test]
fn whir_transcript_replay_detects_a_missing_absorb() {
    let (_v, mut events) = load();

    // Drop the first absorb after the opener, so the stream stays well-formed and
    // only loses a step.
    let drop_at = events
        .iter()
        .skip(1)
        .position(|(op, b)| *op == 0 && !b.is_empty())
        .map(|i| i + 1)
        .expect("the program absorbs more than one event");
    events.remove(drop_at);

    let err = replay(&events).expect_err("a dropped absorb must break the replay");
    println!("dropped absorb rejected as expected: {err}");
}

/// Records the verifier transcript and writes the vector.
///
/// Ignored because it proves (a few seconds) and because it rewrites a checked-in
/// file, which is exactly the property that makes a golden vector useless as a check
/// if it runs by accident (D-052). The always-on tests above read what it wrote.
#[test]
#[ignore = "proves and regenerates a checked-in golden vector; run deliberately"]
fn whir_transcript_vectors() -> Result<(), Box<dyn Error>> {
    let trace = record()?;
    let program = encode(&trace.events);
    let path = vectors_dir().join("whir_transcript_vectors.json");
    std::fs::create_dir_all(path.parent().expect("dir"))?;
    let json = serde_json::json!({
        "hash": "keccak256",
        "note": "the WHIR verifier absorb/squeeze program, recorded from a real verify",
        "num_variables": NUM_VARIABLES,
        "log_rows": LOG_ROWS,
        "events": trace.len(),
        "program": program,
    });
    std::fs::write(&path, serde_json::to_string_pretty(&json).expect("json"))?;
    println!(
        "wrote {} ({} events, {} hex chars)",
        path.display(),
        trace.len(),
        program.len()
    );
    Ok(())
}
