//! The semantic settlement driver: prove a recursion circuit under the
//! recording (semantic) settlement config, verify it natively, and replay the
//! batch transcript phase by phase - the specification BatchTranscript.sol is
//! written from. Moved from `tests/batch_fixture` so the node can encode
//! settlement bundles at runtime with the SAME code the pinned tests exercise.
//!
//! The correctness criterion is unchanged (D-062): the hand-driven replay's
//! event program must equal the native `CircuitVerifier::verify` run's, event
//! for event.

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

use p3_air::symbolic::AirLayout;
use p3_air::BaseAir;
use p3_batch_stark::symbolic::get_log_num_quotient_chunks_for_domain;
use p3_batch_stark::verifier::commitments_with_opening_points;
use p3_batch_stark::{BatchShape, BatchVerifierTranscript};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    poseidon2_air_builders_for_configs, recompose_preprocessor, BatchStarkProver, CircuitVerifier,
    ConstraintProfile, Poseidon2SharedPreprocessor, RecomposeAirBuilder, StatementAirBuilder,
    StatementPreprocessor, StatementProver,
};
use p3_commit::{CommitmentWithOpeningPoints, Pcs, PolynomialSpace, UnivariateStarkPcs};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_lookup::{check_multiplicity_height_bound, LogUpGadget, LookupProtocol};
use p3_recursion::pcs::whir::uni::WhirUniPcs;
use p3_recursion::{Poseidon2Config, ProveNextLayerParams};
use p3_sumcheck::layout::PrefixProver;
use p3_uni_stark::{validate_degree_bits, StarkConfig, StarkGenericConfig};
use serde_json::json;

use crate::semantic_trace::{SemChallenger, SemProgram, SemSink};
pub use crate::whir_recursion::CAP_HEIGHT;
use crate::whir_recursion::{
    build_recursion_circuit, InnerWhirConfig, RecursionCircuit, LOG_MAX_LDE,
};

/// The batch proof's PCS opening argument: one claim per commitment round.
pub type OpeningClaims = Vec<CommitmentWithOpeningPoints<Challenge, Commitment, Dom>>;

/// The WHIR proof behind the opening argument: one `PcsProof` per commitment round.
pub type OpeningProof = <SemPcs as Pcs<Challenge, SemChallenger>>::Proof;

/// A replacement for the native PCS inside the batch delegate: same challenger, same
/// claims, same proof, same error surface (Ok only when every check passed).
pub type OpeningReplacer<'a> = dyn FnMut(
        &mut SemChallenger,
        &OpeningClaims,
        &OpeningProof,
        Option<usize>,
        &SemSink,
    ) -> Result<(), String>
    + 'a;

/// Base field.
pub type F = KoalaBear;
/// Quartic challenge field the settlement WHIR config folds into.
pub type Challenge = BinomialExtensionField<F, 4>;
/// The settlement DFT.
pub type Dft = crate::whir::Dft;
/// The settlement MMCS (Keccak wire-cap Merkle tree).
pub type Mmcs = crate::config::Mmcs;
/// The commitment type the transcript absorbs.
pub type Commitment = <Mmcs as p3_commit::Mmcs<F>>::Commitment;
/// The semantic PCS: the WHIR core over a recording challenger.
pub type SemPcs = WhirUniPcs<Challenge, F, Dft, Mmcs, SemChallenger, PrefixProver<F, Challenge>>;
/// The semantic settlement config: same PCS and field as production, recording challenger.
pub type SemConfig = StarkConfig<SemPcs, Challenge, SemChallenger>;
/// The evaluation domain the settlement PCS opens over.
pub type Dom = <SemPcs as Pcs<Challenge, SemChallenger>>::Domain;
/// The extension degree the settlement circuit is witnessed at.
pub const EXT_DEG: usize = 4;

/// Base trace height of the Fibonacci statement this fixture proves.
pub const BASE_TRACE: usize = 1024;
/// Independent proving runs; two is the minimum that separates fixed from varying.
pub const RUNS: usize = 2;

/// A recording challenger bound to sink, wrapping the production Keccak challenger.
#[must_use]
pub fn sem_challenger_with(sink: &SemSink) -> SemChallenger {
    let inner =
        SerializingChallenger32::new(HashChallenger::new(Vec::new(), p3_keccak::Keccak256Hash {}));
    SemChallenger::new(inner, sink.clone())
}

/// The WHIR protocol parameters the settlement config uses, replicated exactly: the
/// grinding budget is derived from `log_max_lde + ZK_ARITY_SLACK`, and the verifier
/// recomputes the WHIR schedule from these parameters, so a mismatch fails the opening.
#[must_use]
pub fn settlement_params() -> p3_whir::parameters::ProtocolParameters {
    settlement_params_for(LOG_MAX_LDE, 1)
}

/// The same budget derived for an arbitrary `log_max_lde`. The block circuit
/// settles at a larger LDE (25) than the recursion circuit (22), and the grind
/// budget is read off the config's own arity, so the fixture must build either.
#[must_use]
pub fn settlement_params_for(
    log_max_lde: usize,
    rate: usize,
) -> p3_whir::parameters::ProtocolParameters {
    // D-092 batch 45: optional grinding floor, read once here so EVERY
    // settlement-config path (prover, manual replay, composed export) picks
    // up the same schedule. Default 0 = minimum feasible, unchanged.
    let pow_floor = std::env::var("WHIR_POW_FLOOR")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    settlement_params_pow(log_max_lde, rate, pow_floor)
}

/// [`settlement_params_for`] with a grinding FLOOR: the schedule uses
/// `max(minimum feasible, pow_floor)`. Extra grinding buys fewer STIR
/// queries (D-092 batch 45 grid: pow 24->32 cuts final-layer queries
/// 96->85 at rate 4); the prover pays 2^floor hashes per grind point, so
/// the floor is an explicit prover-time/security dial, never a default.
#[must_use]
pub fn settlement_params_pow(
    log_max_lde: usize,
    rate: usize,
    pow_floor: usize,
) -> p3_whir::parameters::ProtocolParameters {
    let mut pow_bits =
        crate::whir::required_pow_bits_with(log_max_lde + crate::whir::ZK_ARITY_SLACK, rate)
            .expect("settlement shape reaches the security target");
    if pow_floor > pow_bits {
        pow_bits = pow_floor;
    }
    p3_whir::parameters::ProtocolParameters {
        pow_bits,
        starting_log_inv_rate: rate,
        ..crate::whir::protocol_params()
    }
}

/// A semantic settlement config whose challenger records into sink.
#[must_use]
pub fn sem_config(sink: &SemSink) -> SemConfig {
    sem_config_for(sink, LOG_MAX_LDE, 1)
}

/// `sem_config` at an explicit `log_max_lde`.
#[must_use]
pub fn sem_config_for(sink: &SemSink, log_max_lde: usize, rate: usize) -> SemConfig {
    let pcs = SemPcs::new(
        settlement_params_for(log_max_lde, rate),
        Dft::default(),
        crate::config::mmcs(CAP_HEIGHT),
        sem_challenger_with(sink),
        log_max_lde,
    );
    StarkConfig::new(pcs, sem_challenger_with(sink))
}

/// The witnessed recursion circuit for one Fibonacci proof, with its statement.
#[must_use]
pub fn fib_recursion() -> (Vec<F>, RecursionCircuit) {
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
/// This is `crate::whir_recursion::settle_recursion_circuit` replicated for the semantic
/// config. The preprocessors depend only on the base field and the AIR builders and table
/// provers are generic over SC, so the relation is identical and only the transcript
/// differs - which is the point.
#[must_use]
pub fn settle_sem(
    rc: &RecursionCircuit,
    sink: &SemSink,
) -> (
    CircuitVerifier<SemConfig>,
    p3_circuit_prover::BatchStarkProof<SemConfig>,
) {
    settle_sem_for(rc, sink, LOG_MAX_LDE, 1)
}

/// `settle_sem` at an explicit `log_max_lde` (the block circuit settles at 25).
#[must_use]
pub fn settle_sem_for(
    rc: &RecursionCircuit,
    sink: &SemSink,
    log_max_lde: usize,
    rate: usize,
) -> (
    CircuitVerifier<SemConfig>,
    p3_circuit_prover::BatchStarkProof<SemConfig>,
) {
    let settlement = sem_config_for(sink, log_max_lde, rate);
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
pub fn ext_json(v: &Challenge) -> Vec<u32> {
    <Challenge as BasedVectorSpace<F>>::as_basis_coefficients_slice(v)
        .iter()
        .map(PrimeField32::as_canonical_u32)
        .collect()
}

/// A base-field element as the contract reads it: canonical u32.
#[must_use]
pub fn base_json(v: F) -> u32 {
    v.as_canonical_u32()
}

/// Lowercase hex, the encoding every pinned vector uses.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut out, "{b:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// A commitment as the transcript absorbs it: concatenated cap roots.
#[must_use]
pub fn com_json(com: &Commitment) -> String {
    let bytes: Vec<u8> = com.roots().iter().flatten().copied().collect();
    hex(&bytes)
}

/// A domain as the contract needs it: log size and shift.
#[must_use]
pub fn dom_json(d: &Dom) -> serde_json::Value {
    json!({
        "log_size": d.size().trailing_zeros(),
        "first_point": base_json(d.first_point()),
    })
}

/// Replicates the private bus layout of `lay_out_lookup_challenges`: global buses share an
/// index by name, local buses take a fresh one, and the widest payload fixes the
/// bus-offset power. Exported as trusted-setup metadata; the on-chain side recomputes the
/// prefixes from alpha, beta and W and checks them against the proof (D-063).
#[must_use]
pub fn bus_layout(lookups: &[p3_lookup::Lookups<F>]) -> (Vec<Vec<usize>>, usize, usize) {
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
#[derive(Debug)]
pub struct ReplayOut {
    /// Event-stream length after each batch-transcript phase, keyed by phase name. The
    /// production contract's absorb counts are pinned against these: run-length merging
    /// hides phase boundaries in the blob schedule, so the marks are the only way the
    /// Solidity side can check it consumed exactly the right prefix at each step.
    pub phase_marks: Vec<(String, usize)>,
    /// The challenge that folds every instance's constraints (`permutation_phase`).
    pub constraint_alpha: Challenge,
    /// The `LogUp` base randomness, recovered as `prefix[0] - beta^W` (see [`beta`]).
    pub lookup_alpha: Challenge,
    /// The `LogUp` payload combiner (`beta`).
    pub beta: Challenge,
    /// The out-of-domain point every opening is taken at.
    pub zeta: Challenge,
    /// Per instance, per lookup: `[bus prefix, beta]`.
    pub challenges: Vec<Vec<Challenge>>,
    /// Per instance: the base-field degree bits read from the proof.
    pub base_degree_bits: Vec<usize>,
    /// Per instance: the LDE domain size the constraint opens over.
    pub ext_domain_sizes: Vec<usize>,
    /// Per instance: the preprocessed column width (0 when no preprocessed).
    pub preprocessed_widths: Vec<usize>,
    /// Per instance: log2 of the quotient chunk count (before the ZK split).
    pub log_num_quotient_chunks: Vec<usize>,
    /// Per instance: the quotient chunk count the proof commits to.
    pub num_quotient_chunks: Vec<usize>,
    /// Per instance, per chunk: the domain each quotient chunk vanishes on.
    pub quotient_domains: Vec<Vec<Dom>>,
    /// Per instance, the natural trace domain the constraint selectors and the
    /// periodic-column evaluation are taken on (`natural_domain_for_degree`).
    pub trace_domains: Vec<Dom>,
    /// The opening requests the delegate receives, as pinned JSON (audit).
    pub opening_rounds: Vec<serde_json::Value>,
}

/// Drive the batch transcript phase by phase exactly as `verify_batch` does, into a
/// challenger bound to `sink_manual`. Program equality against the native run is the
/// assertion; this function is the specification BatchTranscript.sol is written from.
#[allow(clippy::too_many_lines)] // one linear replay of verify_batch's phases; splitting it would scatter the sequence the test exists to pin
pub fn manual_replay(
    config: &SemConfig,
    verifier: &CircuitVerifier<SemConfig>,
    proof: &p3_circuit_prover::BatchStarkProof<SemConfig>,
    public_values: &[Vec<F>],
    sink: &SemSink,
    opening: Option<&mut OpeningReplacer<'_>>,
) -> Result<ReplayOut, Box<dyn Error>> {
    let mut marks: Vec<(String, usize)> = Vec::new();
    let mut mark = |name: &str, sink: &SemSink| {
        marks.push((name.to_string(), sink.program().len()));
    };
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

    mark("new", sink);
    transcript.instance_bindings(&batch.degree_bits);
    mark("instance_bindings", sink);
    transcript.main_phase(batch.commitments.main.clone(), public_values);
    mark("main_phase", sink);
    transcript.preprocessed_phase(common.preprocessed.as_ref().map(|g| g.commitment.clone()));
    mark("preprocessed_phase", sink);
    let laid_out = transcript
        .lookup_phase(all_lookups, &gadget, batch.lookup_pow_witness)
        .map_err(|e| format!("{e:?}"))?;
    mark("lookup_phase", sink);
    let terminal_values: Vec<Challenge> = batch
        .lookup_terminals
        .iter()
        .flatten()
        .map(|t| t.0)
        .collect();
    let constraint_alpha =
        transcript.permutation_phase(batch.commitments.permutation.clone(), &terminal_values);
    mark("permutation_phase", sink);
    transcript.quotient_phase(
        batch.commitments.quotient_chunks.clone(),
        batch.commitments.random.clone(),
    );
    mark("quotient_phase", sink);
    let zeta = transcript
        .ood_phase(batch.ood_pow_witness)
        .map_err(|e| format!("{e:?}"))?;
    mark("ood_phase", sink);

    let trace_domains: Vec<Dom> = ext_domain_sizes
        .iter()
        .map(|&sz| pcs.natural_domain_for_degree(sz >> is_zk_usize))
        .collect();

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

    mark("before_delegate", sink);
    let opening_result = transcript.delegate(|ch| match opening {
        // The native path: the real PCS on the batch challenger, exactly as verify_batch runs it.
        None => pcs
            .verify_with_preprocessing(
                coms_to_verify.clone(),
                &batch.opening_proof,
                ch,
                preprocessed_index,
            )
            .map_err(|e| format!("{e:?}")),
        // The composed path: the caller's WHIR walk replaces the PCS on the SAME challenger,
        // so its transcript events land in the same stream the native run produced.
        Some(replacer) => replacer(
            ch,
            &coms_to_verify,
            &batch.opening_proof,
            preprocessed_index,
            sink,
        ),
    });
    transcript.finish();
    mark("after_finish", sink);
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
        phase_marks: marks,
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
        trace_domains,
        opening_rounds,
    })
}

/// One full proving + verification cycle: prove under the semantic config, run the native
/// verifier, replay the phases by hand, and assert program equality.
#[must_use]
pub fn one_run(
    pis: &[F],
    rc: &RecursionCircuit,
    opening: Option<&mut OpeningReplacer<'_>>,
) -> (
    SemProgram,
    ReplayOut,
    CircuitVerifier<SemConfig>,
    p3_circuit_prover::BatchStarkProof<SemConfig>,
) {
    one_run_for(pis, rc, opening, LOG_MAX_LDE, 1)
}

/// `one_run` at an explicit `log_max_lde`.
#[must_use]
pub fn one_run_for(
    pis: &[F],
    rc: &RecursionCircuit,
    opening: Option<&mut OpeningReplacer<'_>>,
    log_max_lde: usize,
    rate: usize,
) -> (
    SemProgram,
    ReplayOut,
    CircuitVerifier<SemConfig>,
    p3_circuit_prover::BatchStarkProof<SemConfig>,
) {
    let sink = SemSink::new();
    let (verifier, proof) = settle_sem_for(rc, &sink, log_max_lde, rate);

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
    let manual_config = sem_config_for(&sink_manual, log_max_lde, rate);
    let out = manual_replay(
        &manual_config,
        &verifier,
        &proof,
        &public_values,
        &sink_manual,
        opening,
    )
    .expect("manual phase replay");
    let p_manual = sink_manual.program();

    assert_eq!(
        p_native, p_manual,
        "the hand-driven phase replay diverged from verify_batch's own transcript"
    );
    (p_native, out, verifier, proof)
}
