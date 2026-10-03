//! Records the transcript at the PROTOCOL level and asks whether that program is
//! fixed by the proof shape.
//!
//! ## The question this answers
//!
//! Pinning the transcript by recorded BYTES failed (decision D-054 and its addendum):
//! rejection sampling and grinding consume a proof-dependent number of draws, so the
//! byte stream differs even between two recordings of the SAME witness. But the byte
//! stream sits below the protocol. The protocol's own requests - observe this digest,
//! sample one extension challenge, sample this many bits - are what a verifier is
//! written against, and those are what this test measures.
//!
//! If the semantic program is identical across witnesses, the settlement verifier can
//! carry it as a constant table and the transcript layer becomes a loop over a fixed
//! schedule. If it is not, the verifier must derive each step from the proof as it
//! goes, which is a larger but still bounded piece of work. Either way this test is
//! what decides it, so it prints the answer rather than only asserting.
//!
//! ## Why the recording is trustworthy
//!
//! The traced config differs from production in exactly one type parameter, and the
//! proof is produced by the PRODUCTION prover and verified through the traced
//! verifier. Verification passing is the check that the recording is faithful: any
//! perturbation of the transcript would desynchronise the challenges and make the
//! proof fail. `SemChallenger` only forwards and logs, so it cannot change behaviour.

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_recursion::pcs::whir::uni::WhirUniPcs;
use p3_sumcheck::layout::PrefixProver;
use p3_uni_stark::StarkConfig;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use prover::config::{mmcs, Mmcs, F};
use prover::semantic_blob::{classify_observations, replay_blob};
use prover::semantic_trace::{SemChallenger, SemEvent, SemProgram, SemSink};
use prover::whir::{required_pow_bits, Challenge, Dft, ZK_ARITY_SLACK};
use std::error::Error;

/// Statement arity and trace height, matching the byte-level recording so the two
/// artifacts describe the same proof.
const NUM_VARIABLES: usize = 16;
const LOG_ROWS: usize = 10;
/// Distinct witnesses to record. Four is enough to tell "fixed by shape" from
/// "happened to agree": grinding alone would desynchronise a byte-level trace within
/// two runs.
const RUNS: usize = 4;

/// The production challenger type, wrapped.
type SemConfig = StarkConfig<SemPcs, Challenge, SemChallenger>;
type SemPcs = WhirUniPcs<Challenge, F, Dft, Mmcs, SemChallenger, PrefixProver<F, Challenge>>;

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

fn sem_challenger_with(sink: &SemSink) -> SemChallenger {
    let inner = SerializingChallenger32::new(HashChallenger::new(Vec::new(), Keccak256Hash {}));
    SemChallenger::new(inner, sink.clone())
}

/// Production config with only the challenger swapped, plus its sink.
fn sem_config() -> (SemConfig, SemSink) {
    let sink = SemSink::new();
    let pcs = SemPcs::new(
        params(),
        Dft::default(),
        mmcs(prover::whir_recursion::CAP_HEIGHT),
        sem_challenger_with(&sink),
        NUM_VARIABLES,
    );
    (StarkConfig::new(pcs, sem_challenger_with(&sink)), sink)
}

/// Width-2 Fibonacci AIR, the same statement the byte-level vectors pin.
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
        let p0: AB::Expr = builder.public_values()[0].into();
        let p1: AB::Expr = builder.public_values()[1].into();
        builder.when_first_row().assert_eq(a, p0);
        builder.when_first_row().assert_eq(b, p1);
        builder.when_transition().assert_eq(a + b, a_next);
        builder.when_transition().assert_eq(a + b * two, b_next);
    }
}

/// A Fibonacci trace of `len` rows seeded by `seed`, with its public values.
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

/// Prove with production, verify through the semantic recorder, return its log.
fn record(seed: u64) -> Result<SemProgram, Box<dyn Error>> {
    let air = FibAir;
    let (trace, pis) = fib(1 << LOG_ROWS, seed);
    let production = prover::whir::config(prover::whir_recursion::CAP_HEIGHT, NUM_VARIABLES)?;
    let proof =
        p3_uni_stark::prove(&production, &air, trace, &pis).map_err(Box::<dyn Error>::from)?;
    let bytes = postcard::to_allocvec(&proof).expect("encode");
    let traced: p3_uni_stark::Proof<SemConfig> =
        postcard::from_bytes(&bytes).expect("decode into the semantic config type");
    let (cfg, sink) = sem_config();
    p3_uni_stark::verify(&cfg, &air, &traced, &pis).map_err(Box::<dyn Error>::from)?;
    Ok(sink.program())
}

/// The schedule operation an artifact event stands for: its kind and its argument.
fn op_of(e: &serde_json::Value) -> (String, usize) {
    let obj = e.as_object().expect("checked by the caller");
    let key = obj.keys().next().expect("checked by the caller").as_str();
    let v = &obj[key];
    let bits = || usize::try_from(v["bits"].as_u64().unwrap_or(0)).unwrap_or(0);
    match key {
        "ObserveBase" => ("o".to_string(), 1),
        "ObserveBytes" => ("O".to_string(), v["bytes"].as_array().map_or(0, Vec::len)),
        "SampleBase" => ("S".to_string(), v["values"].as_array().map_or(0, Vec::len)),
        "CheckWitness" => ("W".to_string(), bits()),
        "SampleUniformBits" => ("U".to_string(), bits()),
        "SampleBits" => ("b".to_string(), bits()),
        "Grind" => ("g".to_string(), bits()),
        other => unreachable!("unknown event variant {other}"),
    }
}

/// The run-length encoded schedule: consecutive identical operations collapse into
/// one table entry. This is the size that becomes the contract schedule table.
fn rle_runs(events: &[serde_json::Value]) -> usize {
    let mut runs = 0usize;
    let mut prev: Option<(String, usize)> = None;
    for e in events {
        let op = op_of(e);
        if prev.as_ref() != Some(&op) {
            runs += 1;
        }
        prev = Some(op);
    }
    runs
}
/// Pins the checked-in semantic program so the artifact cannot silently rot.
///
/// The recording test is `#[ignore]`d because re-proving is nondeterministic (D-052),
/// which means nothing normally re-checks the file on disk. This does: it re-derives
/// the shape from the committed artifact and asserts the numbers the Solidity side is
/// written against. If someone regenerates the vectors with a different config, this
/// fails here rather than in a confusing place in a Solidity test.
#[test]
fn whir_semantic_program_artifact_has_the_pinned_shape() -> Result<(), Box<dyn Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test/vectors/whir_semantic_program.json");
    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("missing {}: {e}", path.display()))?;
    let doc: serde_json::Value = serde_json::from_str(&raw)?;
    let events = doc["events"]
        .as_array()
        .ok_or("artifact has no events array")?;

    let mut counts = [0usize; 7];
    for e in events {
        let Some(obj) = e.as_object() else {
            return Err("event is not an object".into());
        };
        let Some(key) = obj.keys().next() else {
            return Err("event has no variant key".into());
        };
        let i = match key.as_str() {
            "ObserveBase" => 0,
            "ObserveBytes" => 1,
            "SampleBase" => 2,
            "SampleBits" => 3,
            "Grind" => 4,
            "CheckWitness" => 5,
            "SampleUniformBits" => 6,
            other => return Err(format!("unknown event variant {other}").into()),
        };
        counts[i] += 1;
    }
    // These are the numbers the on-chain schedule is generated from. A change here
    // means the config or the AIR changed, and the generated Solidity table is stale.
    assert_eq!(
        events.len(),
        3551,
        "semantic program length changed; regenerate the Solidity schedule table"
    );
    assert_eq!(
        counts,
        [2518, 7, 224, 0, 0, 23, 779],
        "event mix changed: observe_base, observe_bytes, sample, bits, grind, check_witness, uniform_bits"
    );

    // The run-length encoding is what becomes the contract table, so its size is a
    // deployment-relevant number and belongs in the pin.
    let runs = rle_runs(events);
    assert_eq!(
        runs, 147,
        "run-length encoding changed size; the contract schedule table is stale"
    );

    // Config-fixed observation values are the literals the contract carries. Their
    // count is what the generated constant blob must match.
    let fixed = doc["fixed_values"]
        .as_array()
        .ok_or("artifact has no fixed_values array")?
        .iter()
        .filter(|v| !v.is_null())
        .count();
    assert_eq!(
        fixed, 1849,
        "the number of config-fixed observation positions changed"
    );
    println!(
        "semantic artifact pinned: {} events, {} RLE runs, {} config-fixed values",
        events.len(),
        runs,
        fixed
    );

    // The binary blob is what the contract actually reads, so pin its header too.
    // A stale blob is worse than a stale JSON: the Solidity side would follow a
    // schedule that no longer matches the recorded program and desynchronise in a
    // place nobody thought to look.
    let blob_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test/vectors/whir_semantic_program.bin");
    let blob =
        std::fs::read(&blob_path).map_err(|e| format!("missing {}: {e}", blob_path.display()))?;
    assert!(blob.len() > 28, "blob is shorter than its header");
    assert_eq!(&blob[..4], b"WSPR", "blob magic");
    assert_eq!(u16::from_be_bytes([blob[4], blob[5]]), 1, "blob version");
    let schedule_len = usize::from(u16::from_be_bytes([blob[6], blob[7]]));
    assert_eq!(schedule_len, 175, "blob schedule length");
    let be32 = |k: usize| {
        usize::try_from(u32::from_be_bytes([
            blob[8 + k * 4],
            blob[9 + k * 4],
            blob[10 + k * 4],
            blob[11 + k * 4],
        ]))
        .expect("a payload length fits a usize")
    };
    // constants, variables, samples, uniform, witnesses
    let lens = [be32(0), be32(1), be32(2), be32(3), be32(4)];
    assert_eq!(lens, [7396, 2900, 896, 1558, 92], "blob payload lengths");
    assert_eq!(
        blob.len(),
        28 + schedule_len * 4 + lens.iter().sum::<usize>(),
        "blob payload lengths do not cover the file"
    );
    // The constant payload is the config-fixed literals, so its byte count must agree
    // with the classification in the JSON: one word per fixed position.
    assert_eq!(
        lens[0],
        fixed * 4,
        "the blob constant table disagrees with the fixed-value classification"
    );
    println!("blob pinned: {schedule_len} schedule entries, {lens:?} payloads");
    Ok(())
}

#[test]
#[ignore = "proves RUNS times; run deliberately to regenerate the semantic program"]
fn whir_semantic_program() -> Result<(), Box<dyn Error>> {
    let runs: Vec<SemProgram> = (0..RUNS as u64).map(record).collect::<Result<_, _>>()?;
    let base = &runs[0];

    let count = |p: &SemProgram| {
        let mut c = [0usize; 7];
        for e in p {
            let i = match e {
                SemEvent::ObserveBase { .. } => 0,
                SemEvent::ObserveBytes { .. } => 1,
                SemEvent::SampleBase { .. } => 2,
                SemEvent::SampleBits { .. } => 3,
                SemEvent::Grind { .. } => 4,
                SemEvent::CheckWitness { .. } => 5,
                SemEvent::SampleUniformBits { .. } => 6,
            };
            c[i] += 1;
        }
        c
    };
    let c0 = count(base);
    println!(
        "semantic program: {} events = {} observe_base + {} observe_bytes + {} sample + {} bits + {} grind + {} check_witness + {} uniform_bits",
        base.len(), c0[0], c0[1], c0[2], c0[3], c0[4], c0[5], c0[6]
    );

    let mut differing = 0usize;
    for (r, p) in runs.iter().enumerate().skip(1) {
        assert_eq!(
            p.len(),
            base.len(),
            "run {r} issued {} transcript operations, run 0 issued {}; the semantic program is not shape-stable",
            p.len(),
            base.len()
        );
        for (i, (a, b)) in p.iter().zip(base.iter()).enumerate() {
            let same_kind = std::mem::discriminant(a) == std::mem::discriminant(b);
            if !same_kind {
                differing += 1;
                println!("run {r} site {i}: kind {a:?} vs {b:?}");
                continue;
            }
            // Kind and SHAPE must match exactly. VALUES may legitimately differ: they
            // are digests and challenges drawn from a proof-dependent sponge.
            let shape = |e: &SemEvent| -> (u8, usize, usize) {
                match e {
                    SemEvent::ObserveBase { .. } => (0, 0, 0),
                    SemEvent::ObserveBytes { bytes } => (1, bytes.len(), 0),
                    SemEvent::SampleBase { values } => (2, values.len(), 0),
                    SemEvent::SampleBits { bits, .. } => (3, *bits, 0),
                    SemEvent::Grind { bits, .. } => (4, *bits, 0),
                    SemEvent::CheckWitness { bits, .. } => (5, *bits, 0),
                    SemEvent::SampleUniformBits { bits, .. } => (6, *bits, 0),
                }
            };
            assert_eq!(
                shape(a),
                shape(b),
                "run {r} site {i} changed shape: {a:?} vs {b:?}"
            );
        }
    }
    println!(
        "semantic program shape identical across {RUNS} witnesses ({differing} kind mismatches)"
    );

    // WHICH VALUES ARE CONSTANTS? The shape says what to do at each step; this says
    // which step arguments the contract can hardcode and which it must read from the
    // proof. A position whose value is identical across every witness is fixed by the
    // config, so it belongs in the contract as a literal; one that moves is proof data.
    //
    // Only observation positions are classified. A sampled value is proof-dependent
    // by construction, and a witness check consumes a proof field, so classifying
    // those could only ever answer "varies".
    let (fixed_values, varying_positions) = classify_observations(&runs);
    println!(
        "observation values: {} positions fixed by the config, {} carry proof data (first varying at {:?})",
        fixed_values.iter().filter(|v| v.is_some()).count(),
        varying_positions.len(),
        varying_positions.first()
    );

    // The semantic program is the verifier skeleton. Write it out so the Solidity side
    // is written against the real schedule rather than a guess.
    let json = serde_json::json!({
        "note": "Protocol-level transcript operations for one settlement-shape proof. Recorded by verifying a production proof through a logging challenger; verification passing is the proof that the recording is faithful. Shape is fixed by the config and proof shape; fixed_values marks the observation positions whose value is identical across every recorded witness and so is config-fixed.",
        "num_variables": NUM_VARIABLES,
        "log_rows": LOG_ROWS,
        "runs": RUNS,
        "events": base,
        "fixed_values": fixed_values,
    });
    // COMPLETENESS. Every byte the transcript absorbed must be accounted for by an
    // operation. This is the check that the semantic recording loses nothing: if some
    // observation path were unrecorded, the totals would disagree and the contract
    // would desynchronise at a point the spec cannot even name.
    let observed_bytes = base
        .iter()
        .map(|e| match e {
            // A base observation and a witness check each absorb one 4-byte word.
            SemEvent::ObserveBase { .. } | SemEvent::CheckWitness { .. } => 4,
            SemEvent::ObserveBytes { bytes } => bytes.len(),
            _ => 0,
        })
        .sum::<usize>();
    assert_eq!(
        observed_bytes, 10_388,
        "the semantic recording no longer accounts for every absorbed byte"
    );
    println!("completeness: operations account for all {observed_bytes} absorbed bytes");

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test/vectors/whir_semantic_program.json");
    std::fs::write(&path, serde_json::to_string_pretty(&json)?.into_bytes())?;
    println!("wrote {}", path.display());

    let blob = replay_blob(base, &fixed_values)?;
    let blob_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test/vectors/whir_semantic_program.bin");
    std::fs::write(&blob_path, &blob)?;
    println!("wrote {} ({} bytes)", blob_path.display(), blob.len());
    Ok(())
}
