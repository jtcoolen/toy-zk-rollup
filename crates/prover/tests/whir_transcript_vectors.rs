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

/// Modulus of `KoalaBear`, `2^31 - 2^24 + 1`.
///
/// Checked, not transcribed: `2^31 - 2^27 + 1` is `BabyBear`, and a wrong modulus
/// here would make every rejection-sampling bound in the verifier wrong.
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
        2
    }
}

impl<AB: p3_air::AirBuilder> p3_air::Air<AB> for FibAir {
    fn eval(&self, builder: &mut AB) {
        use p3_air::{AirBuilder as _, WindowAccess as _};
        let main = builder.main();
        let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
        let (a_next, b_next) = (main.next_slice()[0], main.next_slice()[1]);
        let two = AB::F::ONE + AB::F::ONE;
        // The starting pair is the public input rather than a constant, so one
        // AIR shape admits many different witnesses. Varying the witness is what
        // lets the classifier tell a proof-data absorb from a config-fixed label.
        let p0: AB::Expr = builder.public_values()[0].into();
        let p1: AB::Expr = builder.public_values()[1].into();
        builder.when_first_row().assert_eq(a, p0);
        builder.when_first_row().assert_eq(b, p1);
        builder.when_transition().assert_eq(a + b, a_next);
        builder.when_transition().assert_eq(a + b * two, b_next);
    }
}

/// A width-2 Fibonacci trace with a chosen starting pair.
///
/// The seed exists so the SAME statement shape can be proved with DIFFERENT
/// witnesses. That is what separates a transcript absorb that carries proof data
/// from one that is fixed by the config: vary the witness and see what moves.
fn fib(len: usize, seed: u64) -> (p3_matrix::dense::RowMajorMatrix<F>, Vec<F>) {
    let a0 = F::from_u64(1 + seed);
    let mut values = vec![F::ZERO; len * 2];
    values[0] = a0;
    values[1] = F::ONE;
    for i in 1..len {
        let a = values[(i - 1) * 2];
        let b = values[(i - 1) * 2 + 1];
        values[i * 2] = a + b;
        values[i * 2 + 1] = a + (b + b);
    }
    let a0 = values[0];
    let b0 = values[1];
    (
        p3_matrix::dense::RowMajorMatrix::new(values, 2),
        vec![a0, b0],
    )
}

/// Records the verifier's transcript for one real WHIR proof.
fn record() -> Result<TranscriptTrace, Box<dyn Error>> {
    let air = FibAir;
    let (trace, pis) = fib(1 << LOG_ROWS, 0);

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

/// Classifies every absorb as config-fixed or proof-carrying, by RECORDING
/// several witnesses and seeing what moves.
///
/// # Why this is the artifact the verifier core needs
///
/// A Solidity verifier has to know, for each absorb in the transcript, whether
/// the bytes come from the CONFIG (so they can be constants in the contract, and
/// a wrong one is a build-time bug) or from the PROOF (so they must be read out of
/// the calldata, and a wrong one is a soundness bug). Nothing in the Rust source
/// states that split in a form a verifier author can consume. Reading it would
/// mean re-deriving the schedule by hand, which is the circularity D-053 rejects.
///
/// So the split is MEASURED. Prove the same AIR shape with several different
/// witnesses and verify each. An absorb whose bytes are identical across every run
/// cannot depend on the witness, so it is fixed by the config. An absorb that
/// differs must be carrying proof data. No inference, no reading, no guess.
///
/// The same run also settles what IS fixed by the config, which turned out not to be
/// what the first version of this test assumed. See `whir_transcript_program` for
/// the finding: the ABSORB stream is shape-stable, the SQUEEZE stream is not,
/// because `KoalaBear` rejection sampling consumes a proof-dependent byte count.
const RUNS: usize = 4;

/// Op codes for the classified program encoding.
///
/// Absorbs are split by whether they are config-fixed. Squeezes are not split
/// because they are derived, never supplied: the verifier produces them, it does
/// not read them. Their recorded values are kept as a fixture to check against.
const OP_ABSORB_CONSTANT: u8 = 0;
const OP_SQUEEZE: u8 = 1;
const OP_ABSORB_VARIABLE: u8 = 2;

/// Encodes a classified program: op byte, four-byte little-endian length, payload.
fn encode_classified(ops: &[u8], payloads: &[Vec<u8>]) -> String {
    let mut out = String::new();
    for (op, bytes) in ops.iter().zip(payloads) {
        out.push_str(&hex(&[*op]));
        let len = u32::try_from(bytes.len()).expect("an event fits u32");
        out.push_str(&hex(&len.to_le_bytes()));
        out.push_str(&hex(bytes));
    }
    out
}

/// Records one verify of a witness seeded by `seed`.
fn record_with_seed(seed: u64) -> Result<TranscriptTrace, Box<dyn Error>> {
    let air = FibAir;
    let (trace, pis) = fib(1 << LOG_ROWS, seed);
    let production = config(prover::whir_recursion::CAP_HEIGHT, NUM_VARIABLES)?;
    let proof =
        p3_uni_stark::prove(&production, &air, trace, &pis).map_err(Box::<dyn Error>::from)?;
    let bytes = postcard::to_allocvec(&proof).expect("encode");
    let traced_proof: p3_uni_stark::Proof<TracedConfig> =
        postcard::from_bytes(&bytes).expect("decode into the traced config type");
    let (traced, sink) = traced_config();
    p3_uni_stark::verify(&traced, &air, &traced_proof, &pis).map_err(Box::<dyn Error>::from)?;
    Ok(sink.trace())
}

/// Payload bytes of event `i` of `trace`.
fn payload(trace: &TranscriptTrace, i: usize) -> &[u8] {
    match &trace.events[i] {
        Event::Observe { bytes, .. } | Event::Sample { bytes, .. } => bytes,
    }
}

/// Is event `i` a squeeze?
fn is_squeeze(trace: &TranscriptTrace, i: usize) -> bool {
    matches!(trace.events[i], Event::Sample { .. })
}

/// The transcript as SITES: maximal runs of squeezes collapsed into one squeeze site
/// that reports the total bytes drawn, absorbs left as single sites.
///
/// This is the level the protocol is actually specified at, and the level a verifier
/// is written at. A squeeze site is one call to a sampler; how many 32-bit draws that
/// call makes is rejection sampling, so its byte count is proof-dependent while its
/// EXISTENCE AND POSITION are not. Splitting the stream this way is what turns "the
/// event stream is not shape-stable" from a dead end into a usable specification.
fn sites_of(trace: &TranscriptTrace) -> Vec<(bool, usize)> {
    let mut out: Vec<(bool, usize)> = Vec::new();
    let mut i = 0;
    while i < trace.len() {
        if is_squeeze(trace, i) {
            let mut total = 0usize;
            while i < trace.len() && is_squeeze(trace, i) {
                total += payload(trace, i).len();
                i += 1;
            }
            out.push((true, total));
        } else {
            out.push((false, payload(trace, i).len()));
            i += 1;
        }
    }
    out
}

/// Records `RUNS` witnesses of one shape and classifies every absorb as
/// config-fixed or proof-carrying.
///
/// # What this measures, and the surprise it measured
///
/// A Solidity verifier must know, per absorb, whether the bytes come from the
/// CONFIG (so they can be contract constants, and getting one wrong is a
/// build-time bug) or from the PROOF (so they must be read out of calldata, and
/// getting one wrong is a soundness bug). The Rust source does not state that
/// split in a form a verifier author can use, and re-deriving it by hand is the
/// circularity D-053 rejects. So it is MEASURED: prove the same AIR shape with
/// several different witnesses, verify each, and see which absorbs moved.
///
/// The first version of this test asserted that the whole event stream is
/// shape-stable. It FAILED: two proofs of one shape produced 6896 and 6904
/// events. That is the protocol, not noise. `KoalaBear` sampling is rejection
/// sampling - draw 32 bits, reject at or above the modulus, draw again - so how
/// many draws a squeeze needs depends on the sponge state, which depends on the
/// proof. The squeeze stream is proof-dependent in LENGTH as well as value.
///
/// Absorbs are different in kind: the verifier absorbs a fixed set of labels
/// interleaved with a fixed set of proof fields, in an order the config sets. So
/// the ABSORB subsequence is the comparable one, and it is the half the verifier
/// hardcodes. This test asserts that alignment holds, which is the load-bearing
/// claim.
///
/// # The consequence for the verifier, stated plainly
///
/// The verifier cannot be a replay of a recorded op list, because the op list is
/// not fixed. It has to implement the labelled transcript ALGORITHM, with the
/// labels as constants and rejection sampling inside the samplers. The recorded
/// stream stays valuable as a fixture pinning the sponge, the byte order and the
/// label order against a real transcript - but it is a test vector, not the
/// program. That is a correction to how D-053 framed the endgame.
/// Absorb payloads of one trace, in order, squeezes dropped.
fn absorbs_of(t: &TranscriptTrace) -> Vec<Vec<u8>> {
    (0..t.len())
        .filter(|&i| !is_squeeze(t, i))
        .map(|i| payload(t, i).to_vec())
        .collect()
}

/// Asserts the load-bearing claim: the absorb subsequence is fixed by the config
/// and the proof SHAPE, not by the proof VALUE.
///
/// Reports the per-run event and kind counts first, so a failure says what
/// actually varied instead of just failing.
fn assert_absorb_schedule(runs: &[TranscriptTrace]) {
    let kinds = |t: &TranscriptTrace| -> (usize, usize) {
        let mut obs = 0usize;
        let mut sam = 0usize;
        for i in 0..t.len() {
            if is_squeeze(t, i) {
                sam += 1;
            } else {
                obs += 1;
            }
        }
        (obs, sam)
    };
    let (b_obs, b_sam) = kinds(&runs[0]);
    println!(
        "run 0: {} events = {b_obs} absorbs + {b_sam} squeezes",
        runs[0].len()
    );
    for (r, run) in runs.iter().enumerate().skip(1) {
        let (o, s) = kinds(run);
        println!("run {r}: {} events = {o} absorbs + {s} squeezes", run.len());
    }

    let lens: Vec<Vec<usize>> = runs
        .iter()
        .map(|t| absorbs_of(t).iter().map(Vec::len).collect())
        .collect();
    for (r, l) in lens.iter().enumerate().skip(1) {
        assert_eq!(
            l.len(),
            lens[0].len(),
            "run {r} absorbed {} events, run 0 absorbed {}; the absorb schedule is not shape-stable",
            l.len(),
            lens[0].len()
        );
        for (i, len) in l.iter().enumerate() {
            assert_eq!(
                *len, lens[0][i],
                "absorb {i} is {len} bytes in run {r} and {} in run 0",
                lens[0][i]
            );
        }
    }
    println!("absorb schedule identical across all runs: {b_obs} absorbs");

    // THE INVARIANT THAT ACTUALLY MATTERS: the absorb BYTE STREAM.
    //
    // Event boundaries here are a granularity artifact of the p3 challenger, not
    // protocol semantics. Some values reach the byte challenger as one slice and
    // some one byte at a time, so one 32-byte digest can appear as a single
    // 32-byte absorb or as 32 one-byte absorbs. Both leave the sponge in the same
    // state, because absorbing bytes one at a time and absorbing them as a run are
    // the same operation on the stream.
    //
    // So the claim a verifier can rely on is about BYTES. Asserting event counts
    // alone would let a granularity change pass unnoticed; asserting byte totals
    // catches the thing that has meaning.
    let totals: Vec<usize> = lens.iter().map(|l| l.iter().sum()).collect();
    for (r, tot) in totals.iter().enumerate().skip(1) {
        assert_eq!(
            *tot,
            totals[0],
            "run {r} absorbed {tot} bytes, run 0 absorbed {}; the absorb byte stream is not shape-stable",
            totals[0]
        );
    }
    println!(
        "absorb byte stream identical across all runs: {} bytes",
        totals[0]
    );

    // THE SPECIFICATION A VERIFIER IS WRITTEN AT: the SITE sequence.
    //
    // Collapsing each maximal run of squeezes into one site gives a sequence that IS
    // shape-stable, which is the claim the raw event stream failed. Site kinds and
    // positions, and every absorb site size, are identical across runs; only the byte
    // count inside a squeeze site varies, and only because rejection sampling draws
    // until it lands under the modulus.
    let all_sites: Vec<Vec<(bool, usize)>> = runs.iter().map(sites_of).collect();
    for (r, s) in all_sites.iter().enumerate().skip(1) {
        assert_eq!(
            s.len(),
            all_sites[0].len(),
            "run {r} has {} sites, run 0 has {}; the site sequence is not shape-stable",
            s.len(),
            all_sites[0].len()
        );
        for (i, (kind, len)) in s.iter().enumerate() {
            let (k0, l0) = all_sites[0][i];
            assert_eq!(*kind, k0, "site {i} changed kind in run {r}");
            if !k0 {
                assert_eq!(*len, l0, "absorb site {i} changed size in run {r}");
            }
        }
    }
    let n_sqz = all_sites[0].iter().filter(|(k, _)| *k).count();
    println!(
        "site sequence stable across all runs: {} sites = {} absorbs + {} squeeze sites",
        all_sites[0].len(),
        all_sites[0].len() - n_sqz,
        n_sqz
    );

    // Every absorb is either one byte or a four-byte field element. That is not a
    // coincidence to tolerate, it is the shape of the transcript: the labelled layer
    // packs everything through FieldUnit, so labels and field values arrive as
    // four-byte elements, and the byte-at-a-time path carries the rest. A fifth
    // width would mean the recording captured something the verifier has no rule
    // for.
    for (i, l) in lens[0].iter().enumerate() {
        assert!(
            *l == 1 || *l == 4,
            "absorb {i} is {l} bytes, which is neither a single byte nor a field element"
        );
    }
}

#[test]
#[ignore = "proves RUNS times and rewrites a checked-in vector; run deliberately"]
fn whir_transcript_program() -> Result<(), Box<dyn Error>> {
    let runs: Vec<TranscriptTrace> = (0..RUNS as u64)
        .map(record_with_seed)
        .collect::<Result<Vec<_>, _>>()?;

    let base = &runs[0];
    assert_absorb_schedule(&runs);
    let b_obs = absorbs_of(base).len();

    // Classify each absorb position by whether its BYTES are run-independent.
    // Counts accumulate in this same pass rather than in a second scan.
    let all_absorbs: Vec<Vec<Vec<u8>>> = runs.iter().map(absorbs_of).collect();
    let mut constant_bytes = 0usize;
    let mut variable_bytes = 0usize;
    let mut n_const = 0usize;
    let mut n_var = 0usize;
    let mut classes: Vec<u8> = Vec::with_capacity(b_obs);
    for i in 0..b_obs {
        let first = &all_absorbs[0][i];
        if all_absorbs.iter().all(|a| &a[i] == first) {
            constant_bytes += first.len();
            n_const += 1;
            classes.push(OP_ABSORB_CONSTANT);
        } else {
            variable_bytes += first.len();
            n_var += 1;
            classes.push(OP_ABSORB_VARIABLE);
        }
    }

    // Non-vacuity in both directions. All-constant would mean the witness never
    // reached the transcript, i.e. the recording captured a transcript that
    // ignores the proof. All-variable would mean nothing is hardcodable, i.e. the
    // verifier has no constants to carry. Either way the classifier, not the
    // protocol, is what broke.
    assert!(
        constant_bytes > 0,
        "no absorb was witness-independent: nothing is hardcodable"
    );
    assert!(
        variable_bytes > 0,
        "every absorb was witness-independent: the recording ignored the proof"
    );

    // Emit TWO views of the same recording, because they answer two different
    // questions and conflating them is what made the first version of this test fail.
    //
    //   `program` - the raw event stream of run 0, every absorb classified. This is
    //     the fixture: it pins the sponge, the byte order and the label ORDER, and
    //     Solidity replays it byte for byte. It is NOT a program; its squeeze events
    //     are one proof's draw counts.
    //
    //   `sites` - the same stream with each maximal run of squeezes collapsed into
    //     one squeeze site. THIS is the shape a verifier is written against: 2847
    //     sites, of which 82 are squeeze sites at positions fixed by the config, and
    //     the only thing a proof changes is how many bytes it draws at each.
    let mut ops = Vec::with_capacity(base.len());
    let mut payloads = Vec::with_capacity(base.len());
    let mut next_absorb = 0usize;
    for i in 0..base.len() {
        if is_squeeze(base, i) {
            ops.push(OP_SQUEEZE);
            payloads.push(payload(base, i).to_vec());
        } else {
            ops.push(classes[next_absorb]);
            payloads.push(payload(base, i).to_vec());
            next_absorb += 1;
        }
    }

    // Site view: same op codes, but a squeeze site is one entry carrying the total
    // bytes run 0 drew there. A verifier reads the KIND and POSITION as fixed and
    // computes the byte count itself.
    let base_sites = sites_of(base);
    let mut site_ops = Vec::with_capacity(base_sites.len());
    let mut site_payloads: Vec<Vec<u8>> = Vec::with_capacity(base_sites.len());
    let mut absorb_i = 0usize;
    for (is_sqz, total) in &base_sites {
        if *is_sqz {
            site_ops.push(OP_SQUEEZE);
            // Carry the byte count, not the bytes: the count is the shape, and the
            // bytes are whatever run 0 happened to draw.
            site_payloads.push(
                u32::try_from(*total)
                    .expect("a site fits u32")
                    .to_le_bytes()
                    .to_vec(),
            );
        } else {
            site_ops.push(classes[absorb_i]);
            site_payloads.push(all_absorbs[0][absorb_i].clone());
            absorb_i += 1;
        }
    }
    let n_sqz_sites = base_sites.iter().filter(|(k, _)| *k).count();

    let path = vectors_dir().join("whir_transcript_program.json");
    let json = serde_json::json!({
        "hash": "keccak256",
        "note": "WHIR transcript absorb schedule, classified by measurement over RUNS witnesses. Squeeze payloads are run-0 only: squeeze LENGTH is proof-dependent (KoalaBear rejection sampling), so the verifier implements the algorithm rather than replaying this.",
        "runs": RUNS,
        "num_variables": NUM_VARIABLES,
        "log_rows": LOG_ROWS,
        "events_run0": base.len(),
        "absorbs": b_obs,
        "absorb_constant_count": n_const,
        "absorb_variable_count": n_var,
        "absorb_constant_bytes": constant_bytes,
        "absorb_variable_bytes": variable_bytes,
        "sites": base_sites.len(),
        "squeeze_sites": n_sqz_sites,
        "program": encode_classified(&ops, &payloads),
        "site_program": encode_classified(&site_ops, &site_payloads),
    });
    std::fs::write(&path, serde_json::to_string_pretty(&json).expect("json"))?;
    println!(
        "wrote {}: {} absorbs, {} constant ({} bytes), {} variable ({} bytes)",
        path.display(),
        b_obs,
        n_const,
        constant_bytes,
        n_var,
        variable_bytes
    );
    Ok(())
}
