//! Batch-STARK transcript vectors: the layer the settlement contract wraps around the WHIR
//! opening argument.
//!
//! ~~~text
//! cargo test -p prover --test batch_stark_vectors -- --ignored --nocapture
//! ~~~
//!
//! # What this pins
//!
//! The settlement proof is a `BatchStarkProof`; its WHIR proof is that batch proof's
//! `opening_proof`. The contract must therefore replay `p3_batch_stark::verify_batch` with
//! the WHIR core as its PCS layer. M1-M4 ported the WHIR core; this file pins the batch
//! transcript that runs before and around the delegated opening argument:
//!
//! ~~~text
//! new(BatchShape) -> instance_bindings(degree_bits) -> main_phase(main, public_values)
//!   -> preprocessed_phase(Option<com>) -> lookup_phase(lookups, gadget, pow) -> layout
//!   -> permutation_phase(Option<com>, terminals) -> constraint alpha
//!   -> quotient_phase(quotient_com, Option<random_com>) -> ood_phase(pow) -> zeta
//!   -> delegate( pcs.verify_with_preprocessing(coms, opening_proof, ch, idx) )
//!   -> finish()
//! ~~~
//!
//! # The correctness criterion (D-062)
//!
//! The settlement circuit is proven under a SEMANTIC config whose challenger forwards
//! every absorb and sample to the production Keccak challenger and only records (D-061).
//! The test runs the real `verify_batch` under that config (program `P_native`) and a
//! hand-driven phase-by-phase replay (program `P_manual`), and asserts the two event
//! streams are identical. If one absorb or draw were missing, reordered or extra the two
//! would diverge, so the contract's phase sequence is the verifier's sequence by
//! construction rather than by a reading of the source.
//!
//! # Determinism
//!
//! Not deterministic: the WHIR mask is drawn from OS entropy the caller cannot seed. That
//! is also what makes the fixed/varying classification meaningful - a position that never
//! moves across runs is fixed by the config, one that moves carries proof data. The
//! artifacts are pinned snapshots; the non-ignored test re-checks their shape so a stale
//! file fails loudly.
#![recursion_limit = "256"]

use std::error::Error;
use std::path::PathBuf;

use p3_air::symbolic::AirLayout;
use p3_air::BaseAir;
use p3_batch_stark::symbolic::get_log_num_quotient_chunks_for_domain;
use p3_batch_stark::verifier::commitments_with_opening_points;
use p3_batch_stark::{BatchShape, BatchVerifierTranscript, CommonData};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    poseidon2_air_builders_for_configs, recompose_preprocessor, BatchStarkProver, CircuitVerifier,
    ConstraintProfile, Poseidon2SharedPreprocessor, RecomposeAirBuilder, StatementAirBuilder,
    StatementPreprocessor, StatementProver,
};
use p3_commit::{Pcs, PolynomialSpace, UnivariateStarkPcs};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_lookup::{check_multiplicity_height_bound, LogUpGadget, Lookup, LookupProtocol};
use p3_recursion::pcs::whir::uni::WhirUniPcs;
use p3_recursion::{Poseidon2Config, ProveNextLayerParams};
use p3_sumcheck::layout::PrefixProver;
use p3_uni_stark::{validate_degree_bits, StarkConfig, StarkGenericConfig};
use serde_json::json;

use prover::semantic_blob::{classify_observations, replay_blob};
use prover::semantic_trace::{SemChallenger, SemProgram, SemSink};
use prover::whir_recursion::{
    build_recursion_circuit, InnerWhirConfig, RecursionCircuit, CAP_HEIGHT, LOG_MAX_LDE,
};

/// Base field.
type F = KoalaBear;
/// Quartic challenge field the settlement WHIR config folds into.
type Challenge = BinomialExtensionField<F, 4>;
/// The settlement DFT.
type Dft = prover::whir::Dft;
/// The settlement MMCS (Keccak wire-cap Merkle tree).
type Mmcs = prover::config::Mmcs;
/// The commitment type the transcript absorbs.
type Commitment = <Mmcs as p3_commit::Mmcs<F>>::Commitment;
/// The semantic PCS: the WHIR core over a recording challenger.
type SemPcs = WhirUniPcs<Challenge, F, Dft, Mmcs, SemChallenger, PrefixProver<F, Challenge>>;
/// The semantic settlement config: same PCS and field as production, recording challenger.
type SemConfig = StarkConfig<SemPcs, Challenge, SemChallenger>;
/// The evaluation domain the settlement PCS opens over.
type Dom = <SemPcs as Pcs<Challenge, SemChallenger>>::Domain;
/// The extension degree the settlement circuit is witnessed at.
const EXT_DEG: usize = 4;

/// Base trace height of the Fibonacci statement this fixture proves.
const BASE_TRACE: usize = 1024;
/// Independent proving runs; two is the minimum that separates fixed from varying.
const RUNS: usize = 2;

/// A recording challenger bound to sink, wrapping the production Keccak challenger.
fn sem_challenger_with(sink: &SemSink) -> SemChallenger {
    let inner =
        SerializingChallenger32::new(HashChallenger::new(Vec::new(), p3_keccak::Keccak256Hash {}));
    SemChallenger::new(inner, sink.clone())
}

/// The WHIR protocol parameters the settlement config uses, replicated exactly: the
/// grinding budget is derived from `log_max_lde + ZK_ARITY_SLACK`, and the verifier
/// recomputes the WHIR schedule from these parameters, so a mismatch fails the opening.
fn settlement_params() -> p3_whir::parameters::ProtocolParameters {
    let pow_bits = prover::whir::required_pow_bits(LOG_MAX_LDE + prover::whir::ZK_ARITY_SLACK)
        .expect("settlement shape reaches the security target");
    p3_whir::parameters::ProtocolParameters {
        pow_bits,
        ..prover::whir::protocol_params()
    }
}

/// A semantic settlement config whose challenger records into sink.
fn sem_config(sink: &SemSink) -> SemConfig {
    let pcs = SemPcs::new(
        settlement_params(),
        Dft::default(),
        prover::config::mmcs(CAP_HEIGHT),
        sem_challenger_with(sink),
        LOG_MAX_LDE,
    );
    StarkConfig::new(pcs, sem_challenger_with(sink))
}

/// The witnessed recursion circuit for one Fibonacci proof, with its statement.
fn fib_recursion() -> (Vec<F>, RecursionCircuit) {
    let inner = InnerWhirConfig::new(LOG_MAX_LDE, CAP_HEIGHT).expect("inner config");
    let air = FibonacciAir {};
    let trace = generate_trace_rows::<F>(0, 1, BASE_TRACE);
    let mut a = F::ZERO;
    let mut b = F::ONE;
    for _ in 1..BASE_TRACE {
        let n = a + b;
        a = b;
        b = n;
    }
    let pis = vec![F::ZERO, F::ONE, b];
    let base = p3_uni_stark::prove(&inner, &air, trace, &pis).expect("base prove");
    let rc = build_recursion_circuit(&inner, &air, &base, &pis).expect("recursion circuit");
    (pis, rc)
}

/// Prove rc under the semantic settlement config bound to sink.
///
/// This is `prover::whir_recursion::settle_recursion_circuit` replicated for the semantic
/// config. The preprocessors depend only on the base field and the AIR builders and table
/// provers are generic over SC, so the relation is identical and only the transcript
/// differs - which is the point.
fn settle_sem(
    rc: &RecursionCircuit,
    sink: &SemSink,
) -> (
    CircuitVerifier<SemConfig>,
    p3_circuit_prover::BatchStarkProof<SemConfig>,
) {
    let settlement = sem_config(sink);
    let shared = Poseidon2Config::KOALA_BEAR_D4_W16.for_shared_challenger_table();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2SharedPreprocessor::new(vec![shared])),
        recompose_preprocessor::<F>(true),
        Box::new(StatementPreprocessor::new(rc.schema.clone())),
    ];
    let mut air_builders: Vec<Box<dyn NpoAirBuilder<SemConfig, EXT_DEG>>> =
        poseidon2_air_builders_for_configs::<SemConfig, EXT_DEG>(vec![shared]);
    air_builders.push(Box::new(RecomposeAirBuilder::<EXT_DEG>::new(1, true)));
    air_builders.push(Box::new(StatementAirBuilder::<EXT_DEG>::new(
        rc.schema.clone(),
    )));

    let mut prover = BatchStarkProver::new(settlement)
        .with_table_packing(ProveNextLayerParams::default().table_packing);
    prover.register_poseidon2_table::<EXT_DEG>(shared);
    prover.register_recompose_table::<EXT_DEG>(true);
    prover.register_table_prover(Box::new(StatementProver::<EXT_DEG>::new(rc.schema.clone())));
    let prepared = prover
        .prepare_circuit(
            &rc.circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("prepare settlement circuit");
    let proof = prepared.prove(&rc.traces).expect("settlement prove");
    (prepared.verifier(), proof)
}

/// Canonical basis coefficients of an extension element.
fn ext_json(v: &Challenge) -> Vec<u32> {
    <Challenge as BasedVectorSpace<F>>::as_basis_coefficients_slice(v)
        .iter()
        .map(PrimeField32::as_canonical_u32)
        .collect()
}

fn base_json(v: F) -> u32 {
    v.as_canonical_u32()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut out, "{b:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// A commitment as the transcript absorbs it: concatenated cap roots.
fn com_json(com: &Commitment) -> String {
    let bytes: Vec<u8> = com.roots().iter().flatten().copied().collect();
    hex(&bytes)
}

/// A domain as the contract needs it: log size and shift.
fn dom_json(d: &Dom) -> serde_json::Value {
    json!({
        "log_size": d.size().trailing_zeros(),
        "first_point": base_json(d.first_point()),
    })
}

/// One instance's lookup metadata: trusted-setup data, never proof data (D-063).
fn lookup_meta(lookups: &[Lookup<F>]) -> Vec<serde_json::Value> {
    lookups
        .iter()
        .map(|l| {
            let widths: Vec<usize> = l.elements.iter().map(Vec::len).collect();
            let first = widths.first().copied().unwrap_or(0);
            assert!(
                widths.iter().all(|w| *w == first),
                "lookup tuples sharing a bus must share a width"
            );
            json!({
                "kind": match &l.kind {
                    p3_lookup::Kind::Global(name) => json!({"global": name}),
                    p3_lookup::Kind::Local => json!("local"),
                },
                "num_tuples": l.elements.len(),
                "tuple_width": first,
            })
        })
        .collect()
}

/// Replicates the private bus layout of `lay_out_lookup_challenges`: global buses share an
/// index by name, local buses take a fresh one, and the widest payload fixes the
/// bus-offset power. Exported as trusted-setup metadata; the on-chain side recomputes the
/// prefixes from alpha, beta and W and checks them against the proof (D-063).
fn bus_layout(lookups: &[p3_lookup::Lookups<F>]) -> (Vec<Vec<usize>>, usize, usize) {
    let mut global_index: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let mut next_bus = 0usize;
    let mut max_message_width = 1usize;
    let ids: Vec<Vec<usize>> = lookups
        .iter()
        .map(|contexts| {
            contexts
                .as_ref()
                .iter()
                .map(|ctx| {
                    let w = ctx.elements.first().map_or(0, Vec::len);
                    max_message_width = max_message_width.max(w);
                    match &ctx.kind {
                        p3_lookup::Kind::Global(name) => {
                            *global_index.entry(name).or_insert_with(|| {
                                let id = next_bus;
                                next_bus += 1;
                                id
                            })
                        }
                        p3_lookup::Kind::Local => {
                            let id = next_bus;
                            next_bus += 1;
                            id
                        }
                    }
                })
                .collect()
        })
        .collect();
    (ids, max_message_width, next_bus)
}

/// What the hand-driven replay recovers: the scalars the contract must reproduce and the
/// derived per-instance shape it recomputes from trusted setup.
struct ReplayOut {
    /// The challenge that folds every instance's constraints (`permutation_phase`).
    constraint_alpha: Challenge,
    /// The `LogUp` base randomness, recovered as `prefix[0] - beta^W` (see [`beta`]).
    lookup_alpha: Challenge,
    /// The `LogUp` payload combiner (`beta`).
    beta: Challenge,
    /// The out-of-domain point every opening is taken at.
    zeta: Challenge,
    /// Per instance, per lookup: `[bus prefix, beta]`.
    challenges: Vec<Vec<Challenge>>,
    base_degree_bits: Vec<usize>,
    ext_domain_sizes: Vec<usize>,
    preprocessed_widths: Vec<usize>,
    log_num_quotient_chunks: Vec<usize>,
    num_quotient_chunks: Vec<usize>,
    quotient_domains: Vec<Vec<Dom>>,
    opening_rounds: Vec<serde_json::Value>,
}

/// Drive the batch transcript phase by phase exactly as `verify_batch` does, into a
/// challenger bound to `sink_manual`. Program equality against the native run is the
/// assertion; this function is the specification BatchTranscript.sol is written from.
#[allow(clippy::too_many_lines)] // one linear replay of verify_batch's phases; splitting it would scatter the sequence the test exists to pin
fn manual_replay(
    config: &SemConfig,
    verifier: &CircuitVerifier<SemConfig>,
    proof: &p3_circuit_prover::BatchStarkProof<SemConfig>,
    public_values: &[Vec<F>],
) -> Result<ReplayOut, Box<dyn Error>> {
    let airs = verifier
        .table_airs::<EXT_DEG>()
        .map_err(|e| format!("{e:?}"))?;
    let common = verifier.common_data();
    let batch = &proof.proof;
    let pcs = config.pcs();
    let is_zk = <SemPcs as UnivariateStarkPcs<Challenge, SemChallenger>>::ZK;
    let is_zk_usize = usize::from(is_zk);
    let gadget = LogUpGadget::new();
    let all_lookups = common.lookups.as_slice();

    // Per-instance derivation, mirroring verify_batch's pre-transcript loop.
    let mut base_degree_bits = Vec::new();
    let mut ext_domain_sizes = Vec::new();
    let mut preprocessed_widths = Vec::new();
    let mut log_num_quotient_chunks = Vec::new();
    let mut num_quotient_chunks = Vec::new();
    for (i, air) in airs.iter().enumerate() {
        let (base_db, ext_size) = validate_degree_bits(
            Some(i),
            batch.degree_bits[i],
            is_zk_usize,
            pcs.log_min_trace_height(),
            pcs.log_max_trace_height(),
        )
        .map_err(|e| format!("{e:?}"))?;
        base_degree_bits.push(base_db);
        ext_domain_sizes.push(ext_size);
        let pre_w = common
            .preprocessed
            .as_ref()
            .and_then(|g| g.instances[i].as_ref().map(|m| m.width))
            .unwrap_or(0);
        preprocessed_widths.push(pre_w);
        let layout = AirLayout {
            preprocessed_width: pre_w,
            main_width: BaseAir::<F>::width(air),
            num_public_values: BaseAir::<F>::num_public_values(air),
            num_periodic_columns: BaseAir::<F>::num_periodic_columns(air),
            ..Default::default()
        };
        let log_chunks = get_log_num_quotient_chunks_for_domain::<_, Challenge, _, _>(
            air,
            layout,
            pcs.natural_domain_for_degree(1usize << base_db),
            all_lookups[i].as_ref(),
            is_zk_usize,
            &gadget,
        );
        log_num_quotient_chunks.push(log_chunks);
        num_quotient_chunks.push(1usize << (log_chunks + is_zk_usize));
    }
    let trace_heights: Vec<usize> = base_degree_bits.iter().map(|&b| 1usize << b).collect();
    check_multiplicity_height_bound(all_lookups, &trace_heights).map_err(|e| format!("{e:?}"))?;

    let num_lookup_instances = all_lookups.iter().filter(|c| !c.is_empty()).count();
    assert_eq!(
        batch.commitments.permutation.is_some(),
        num_lookup_instances > 0,
        "permutation commitment presence must match the lookup instance count"
    );

    let shape = BatchShape {
        trace_widths: airs.iter().map(BaseAir::<F>::width).collect(),
        public_value_counts: airs.iter().map(BaseAir::<F>::num_public_values).collect(),
        preprocessed_widths: preprocessed_widths.clone(),
        has_preprocessed_commitment: common.preprocessed.is_some(),
        num_lookup_instances,
        lookup_pow_bits: config.lookup_proof_of_work_bits(),
        has_randomization_commitment: is_zk,
        ood_pow_bits: config.ood_proof_of_work_bits(),
    };

    let mut challenger = config.initialise_challenger();
    let mut transcript = BatchVerifierTranscript::<SemChallenger, F, Challenge, Commitment>::new(
        &mut challenger,
        shape,
    );

    transcript.instance_bindings(&batch.degree_bits);
    transcript.main_phase(batch.commitments.main.clone(), public_values);
    transcript.preprocessed_phase(common.preprocessed.as_ref().map(|g| g.commitment.clone()));
    let laid_out = transcript
        .lookup_phase(all_lookups, &gadget, batch.lookup_pow_witness)
        .map_err(|e| format!("{e:?}"))?;
    let terminal_values: Vec<Challenge> = batch
        .lookup_terminals
        .iter()
        .flatten()
        .map(|t| t.0)
        .collect();
    let constraint_alpha =
        transcript.permutation_phase(batch.commitments.permutation.clone(), &terminal_values);
    transcript.quotient_phase(
        batch.commitments.quotient_chunks.clone(),
        batch.commitments.random.clone(),
    );
    let zeta = transcript
        .ood_phase(batch.ood_pow_witness)
        .map_err(|e| format!("{e:?}"))?;

    let (coms_to_verify, quotient_domains, preprocessed_index) = commitments_with_opening_points(
        config,
        &airs,
        zeta,
        &batch.commitments,
        &batch.opened_values,
        common,
        &batch.degree_bits,
        &preprocessed_widths,
        &log_num_quotient_chunks,
    )
    .map_err(|e| format!("{e:?}"))?;

    // The opening requests are recorded before the delegate call so the export shows them
    // even if verification fails. Points are inputs, never blob bytes (D-060).
    let opening_rounds = coms_to_verify
        .iter()
        .map(|round| {
            json!({
                "commitment": com_json(&round.commitment),
                "matrices": round.matrices.iter().map(|m| json!({
                    "domain": dom_json(&m.domain),
                    "points": m.points.iter().map(|pt| json!({
                        "point": ext_json(&pt.point),
                        "values": pt.values.iter().map(ext_json).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    let opening_result = transcript.delegate(|ch| {
        pcs.verify_with_preprocessing(coms_to_verify, &batch.opening_proof, ch, preprocessed_index)
    });
    transcript.finish();
    let opening_result: Result<(), String> = opening_result.map_err(|e| format!("{e:?}"));
    opening_result?;

    // The cross-AIR terminal sum: no transcript involvement, but the contract must check
    // it too, so it is checked here.
    gadget
        .verify_terminal_sum(&batch.lookup_terminals)
        .map_err(|e| format!("{e:?}"))?;

    // Recover the LogUp pair from the laid-out challenges. Buses are assigned in order of
    // first appearance, so the first lookup of the first instance sits on bus 0 and its
    // prefix is alpha + gamma with gamma = beta^W.
    let beta = laid_out
        .iter()
        .find_map(|c| c.get(1).copied())
        .ok_or("no lookup challenges")?;
    let first_prefix = laid_out
        .iter()
        .find_map(|c| c.first().copied())
        .ok_or("no lookup challenges")?;
    let (_, w, _) = bus_layout(all_lookups);
    let gamma = beta.exp_u64(w as u64);
    let lookup_alpha = first_prefix - gamma;

    Ok(ReplayOut {
        constraint_alpha,
        lookup_alpha,
        beta,
        zeta,
        challenges: laid_out,
        base_degree_bits,
        ext_domain_sizes,
        preprocessed_widths,
        log_num_quotient_chunks,
        num_quotient_chunks,
        quotient_domains,
        opening_rounds,
    })
}

/// One full proving + verification cycle: prove under the semantic config, run the native
/// verifier, replay the phases by hand, and assert program equality.
fn one_run(
    pis: &[F],
    rc: &RecursionCircuit,
) -> (
    SemProgram,
    ReplayOut,
    CircuitVerifier<SemConfig>,
    p3_circuit_prover::BatchStarkProof<SemConfig>,
) {
    let sink = SemSink::new();
    let (verifier, proof) = settle_sem(rc, &sink);

    // The prover shares the sink; mark where the verifier's program begins.
    let mark = sink.program().len();
    verifier
        .verify(&proof, pis)
        .expect("native settlement verify");
    let native = sink.program();
    let p_native = native[mark..].to_vec();

    // verify_batch takes public values per instance, derived from the statement by the
    // trusted verifier descriptor - never read from the proof.
    let public_values = verifier
        .table_public_values(pis)
        .expect("table public values");

    let sink_manual = SemSink::new();
    let manual_config = sem_config(&sink_manual);
    let out = manual_replay(&manual_config, &verifier, &proof, &public_values)
        .expect("manual phase replay");
    let p_manual = sink_manual.program();

    assert_eq!(
        p_native, p_manual,
        "the hand-driven phase replay diverged from verify_batch's own transcript"
    );
    (p_native, out, verifier, proof)
}

/// Smoke: prove the settlement batch under the semantic config, verify natively, replay
/// the phases by hand, and require the two transcript programs to agree.
#[test]
#[ignore = "proves the settlement batch (~5s); the export test runs this as its first step"]
fn settlement_program_equality() {
    let (pis, rc) = fib_recursion();
    let (program, out, _verifier, _proof) = one_run(&pis, &rc);
    println!("program events: {}", program.len());
    println!("zeta: {:?}", ext_json(&out.zeta));
    println!("constraint alpha: {:?}", ext_json(&out.constraint_alpha));
    println!("lookup alpha: {:?}", ext_json(&out.lookup_alpha));
    println!("beta: {:?}", ext_json(&out.beta));
    println!("instances: {}", out.challenges.len());
}

/// Prove, verify and replay RUNS times, classify every transcript position as config-fixed
/// or proof-varying, and write the artifacts the Solidity side drives from.
#[test]
#[ignore = "proves the settlement batch RUNS times (~5s each); regenerates the artifacts"]
#[allow(clippy::too_many_lines)] // the artifact document is one literal; splitting the json! across helpers hides the schema
fn export_batch_stark_vectors() {
    let (pis, rc) = fib_recursion();
    let mut programs = Vec::new();
    let mut last: Option<(
        ReplayOut,
        CircuitVerifier<SemConfig>,
        p3_circuit_prover::BatchStarkProof<SemConfig>,
    )> = None;
    for _ in 0..RUNS {
        let (program, out, verifier, proof) = one_run(&pis, &rc);
        programs.push(program);
        last = Some((out, verifier, proof));
    }
    let (out, verifier, proof) = last.expect("at least one run");
    let batch = &proof.proof;
    let common: &CommonData<SemConfig> = verifier.common_data();
    let airs = verifier.table_airs::<EXT_DEG>().expect("airs");
    let public_values = verifier.table_public_values(&pis).expect("public values");

    // Fixed/varying classification over the native verifier programs (D-059). The blob
    // and every exported value must describe the SAME proof: each run re-masks, so a
    // blob from run 1 and challenges from run 2 would disagree on every sample.
    let (fixed, varying) = classify_observations(&programs);
    let program = programs.last().expect("at least one run");
    let blob = replay_blob(program, &fixed).expect("replay blob");
    let fixed_runs: Vec<String> = fixed
        .iter()
        .map(|f| {
            f.as_ref().map_or_else(String::new, |v| {
                hex(&v.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>())
            })
        })
        .collect();

    let (bus_ids, max_message_width, next_bus) = bus_layout(&common.lookups);
    // The bus-prefix algebra the contract recomputes: prefix[i] = alpha + (i+1) * beta^W.
    let gamma = out.beta.exp_u64(max_message_width as u64);
    let prefix0 = out.lookup_alpha + gamma;
    assert_eq!(
        <Challenge as BasedVectorSpace<F>>::as_basis_coefficients_slice(&prefix0),
        <Challenge as BasedVectorSpace<F>>::as_basis_coefficients_slice(
            &out.challenges
                .iter()
                .find_map(|c| c.first().copied())
                .expect("a lookup challenge pair")
        ),
        "prefix[0] must equal alpha + gamma"
    );

    let opened = |i: usize| &batch.opened_values.instances[i].base_opened_values;
    let exts = |v: &[Challenge]| v.iter().map(ext_json).collect::<Vec<_>>();
    let doc = json!({
        "description": "batch STARK transcript vectors: settlement BatchStarkProof under the semantic Keccak config",
        "field": "KoalaBear",
        "ext_degree": EXT_DEG,
        "is_zk": <SemPcs as UnivariateStarkPcs<Challenge, SemChallenger>>::ZK,
        "statement": pis.iter().map(|v| base_json(*v)).collect::<Vec<_>>(),
        "degree_bits": batch.degree_bits,
        "base_degree_bits": out.base_degree_bits,
        "ext_domain_sizes": out.ext_domain_sizes,
        "num_instances": airs.len(),
        "instances": (0..airs.len()).map(|i| json!({
            "trace_width": BaseAir::<F>::width(&airs[i]),
            "public_value_count": public_values[i].len(),
            "public_values": public_values[i].iter().map(|v| base_json(*v)).collect::<Vec<_>>(),
            "preprocessed_width": out.preprocessed_widths[i],
            "log_num_quotient_chunks": out.log_num_quotient_chunks[i],
            "num_quotient_chunks": out.num_quotient_chunks[i],
            "has_trace_next": opened(i).trace_next.is_some(),
            "lookups": lookup_meta(common.lookups[i].as_ref()),
            "bus_ids": bus_ids[i],
            "lookup_challenges": out.challenges[i].iter().map(ext_json).collect::<Vec<_>>(),
            "lookup_terminal": batch.lookup_terminals[i].map(|t| ext_json(&t.0)),
            "opened": {
                "trace_local": exts(&opened(i).trace_local),
                "trace_next": opened(i).trace_next.as_ref().map(|v| exts(v)),
                "preprocessed_local": opened(i).preprocessed_local().map(exts),
                "preprocessed_next": opened(i).preprocessed_next().map(exts),
                "quotient_chunks": opened(i).quotient_chunks.iter().map(|c| exts(c)).collect::<Vec<_>>(),
                "random": opened(i).random.as_ref().map(|v| exts(v)),
                "permutation_local": exts(&batch.opened_values.instances[i].permutation_local),
                "permutation_next": exts(&batch.opened_values.instances[i].permutation_next),
            },
        })).collect::<Vec<_>>(),
        "commitments": {
            "main": com_json(&batch.commitments.main),
            "permutation": batch.commitments.permutation.as_ref().map(com_json),
            "quotient_chunks": com_json(&batch.commitments.quotient_chunks),
            "random": batch.commitments.random.as_ref().map(com_json),
            "preprocessed": common.preprocessed.as_ref().map(|g| com_json(&g.commitment)),
        },
        "pow_witnesses": {
            "lookup": batch.lookup_pow_witness.map(base_json),
            "ood": base_json(batch.ood_pow_witness),
        },
        "constraint_alpha": ext_json(&out.constraint_alpha),
        "lookup_alpha": ext_json(&out.lookup_alpha),
        "beta": ext_json(&out.beta),
        "zeta": ext_json(&out.zeta),
        "bus_layout": {
            "max_message_width": max_message_width,
            "next_bus": next_bus,
        },
        "quotient_domains": out.quotient_domains.iter()
            .map(|ds| ds.iter().map(dom_json).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "opening_rounds": out.opening_rounds,
        "fixed_runs": fixed_runs,
        "varying_positions": varying,
        "program_len": program.len(),
        "blob_len": blob.len(),
    });

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    std::fs::create_dir_all(&dir).expect("vectors dir");
    std::fs::write(
        dir.join("batch_stark_vectors.json"),
        serde_json::to_string_pretty(&doc).expect("serialize"),
    )
    .expect("write json");
    std::fs::write(dir.join("batch_stark_vectors.bin"), &blob).expect("write bin");
    println!(
        "wrote batch_stark_vectors.json: {} instances, program {} events, blob {} bytes, {} fixed runs",
        airs.len(),
        program.len(),
        blob.len(),
        fixed.iter().filter(|f| f.is_some()).count()
    );
}

/// Shape pin: the committed artifact must describe the settlement batch this fixture
/// produces. A stale or hand-edited file fails here before the Solidity suite chases a
/// phantom desync.
#[test]
fn batch_stark_artifact_shape_is_pinned() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/test/vectors");
    let Ok(text) = std::fs::read_to_string(dir.join("batch_stark_vectors.json")) else {
        // Absent until the ignored export has been run once.
        return;
    };
    let doc: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    assert_eq!(doc["num_instances"].as_u64().unwrap(), 6);
    assert!(doc["is_zk"].as_bool().unwrap());
    assert_eq!(doc["ext_degree"].as_u64().unwrap(), 4);
    let dbs: Vec<u64> = doc["degree_bits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert_eq!(dbs.len(), 6, "one degree-bit entry per instance");
    assert!(dbs.iter().all(|&d| d > 0 && d <= LOG_MAX_LDE as u64));
    // Every settlement instance carries lookups (measured shape), so the permutation
    // commitment, the randomization commitment and the preprocessed commitment are all
    // present, and both proof-of-work witnesses are the free-search value.
    for inst in doc["instances"].as_array().unwrap() {
        assert!(!inst["lookups"].as_array().unwrap().is_empty());
    }
    assert!(doc["commitments"]["permutation"].is_string());
    assert!(doc["commitments"]["random"].is_string());
    assert!(doc["commitments"]["preprocessed"].is_string());
    assert_eq!(doc["pow_witnesses"]["ood"].as_u64().unwrap(), 0);
    assert_eq!(doc["pow_witnesses"]["lookup"].as_u64().unwrap(), 0);
    // The bus layout is trusted-setup metadata the contract recomputes against.
    assert!(doc["bus_layout"]["max_message_width"].as_u64().unwrap() >= 1);
    assert!(doc["bus_layout"]["next_bus"].as_u64().unwrap() >= 1);

    let bytes = std::fs::read(dir.join("batch_stark_vectors.bin")).expect("blob alongside json");
    assert_eq!(&bytes[0..4], b"WSPR");
    assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 2);
    assert_eq!(bytes.len() as u64, doc["blob_len"].as_u64().unwrap());
}
