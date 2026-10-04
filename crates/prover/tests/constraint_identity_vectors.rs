//! Constraint-identity vectors: the last layer of `verify_batch` after the opening
//! argument. Per instance the contract must check that the folded AIR constraints at
//! the out-of-domain point equal the recomposed quotient:
//!
//! ```text
//! fold(alpha, constraints(zeta)) * inv_vanishing(zeta) == quotient(zeta)
//! ```
//!
//! Run with: `cargo test -p prover --test constraint_identity_vectors -- --ignored --nocapture`
//!
//! # Why an IR export
//!
//! The settlement AIRs are generated (Poseidon2 / recompose / statement tables), so
//! the constraints cannot be hand-written in Solidity. They are trusted-setup data:
//! this file runs `get_symbolic_constraints` on the exact AIRs the verifier
//! reconstructs, flattens each constraint's expression DAG to a post-order op list
//! (shared subtrees emitted once, referenced by node index), and exports every opened
//! value the evaluator consumes. The Solidity side is a DAG interpreter.
//!
//! # The on-chain identity (pinned here before porting)
//!
//! The library check is `fold * inv_vanishing == quotient` with real selectors
//! `is_first = zh/s1`, `is_last = zh/s2`, `is_transition = s2` where the trace
//! domain is `gH` (natural domains have shift 1, so `u = zeta`, `zh = u^(2^L) - 1`,
//! `s1 = u - 1`, `s2 = u - h_inv`). Every denominator (`zh`, `s1`, `s2`) depends only
//! on `zeta` and the domain, never on a constraint, so the contract pays three
//! extension inversions per instance (batchable with Montgomery's trick) instead of
//! reformulating the fold.
//!
//! The quotient recompose inverts `Z_j(first_i)`, which is a domain-only constant:
//! the export carries `invD_i = (prod_{j!=i} Z_j(first_i))^-1` and each chunk
//! domain's `inv_shift_j`, so the contract computes
//! `quotient = sum_i q_i * (prod_{j!=i} Z_j(zeta)) * invD_i` with
//! `Z_j(zeta) = (zeta * inv_shift_j)^(2^Lj) - 1` and no runtime inversion there.
//! The test asserts this reformulation equals the library's
//! `recompose_quotient_from_chunks` before pinning the identity.
#![recursion_limit = "256"]

use std::error::Error;
use std::path::PathBuf;

use p3_air::symbolic::AirLayout;
use p3_air::BaseAir;
use p3_batch_stark::symbolic::get_log_num_quotient_chunks_for_domain;
use p3_batch_stark::verifier::commitments_with_opening_points;
use p3_batch_stark::{BatchShape, BatchVerifierTranscript, CommonData};
use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
use p3_commit::{Mmcs, Pcs, UnivariateStarkPcs};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{LogUpGadget, LookupProtocol};
use p3_uni_stark::{validate_degree_bits, StarkGenericConfig};
use serde_json::json;

use prover::whir::Challenger;
use prover::whir_recursion::{
    build_recursion_circuit, settle_recursion_circuit, RecursionCircuit, CAP_HEIGHT, LOG_MAX_LDE,
};

use prover::constraint_ir::{instance_identity_json, EF};
use prover::settlement_replay::ext_json;
use prover::F;

type WhirPcs = prover::whir::Pcs;
type Config = prover::whir::Config;
type Commitment = <prover::config::Mmcs as Mmcs<F>>::Commitment;

const BASE_TRACE: usize = 1024;

/// The Fibonacci fixture, identical to `batch_stark_vectors.rs`: same statement, same
/// circuit, so the exported IR describes the same batch the transcript blob pins.
fn fib_recursion() -> (Vec<F>, RecursionCircuit) {
    let inner = prover::whir_recursion::InnerWhirConfig::new(LOG_MAX_LDE, CAP_HEIGHT)
        .expect("inner config");
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

fn artifact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test/vectors/constraint_identity_vectors.json")
}

fn boxed<E: core::fmt::Debug>(e: E) -> Box<dyn Error> {
    Box::<dyn Error>::from(format!("{e:?}"))
}

/// Prove the settlement batch, replay the batch transcript to recover `zeta` and the
/// fold challenge, flatten every instance's symbolic constraints to a DAG, evaluate
/// the fold at the opened values and pin `fold * inv_vanishing == quotient`. The
/// flattened IR plus every input the fold consumed is written to the vectors file the
/// Solidity pin test reads.
#[test]
#[ignore = "proves the settlement batch (~6s); regenerates the vectors"]
#[allow(clippy::too_many_lines)] // one linear replay of verify_batch's tail; splitting scatters what it pins
fn export_constraint_identity_vectors() -> Result<(), Box<dyn Error>> {
    let (pis, rc) = fib_recursion();
    let (proof, verifier) = settle_recursion_circuit(&rc, LOG_MAX_LDE)?;
    let config = prover::whir::config(CAP_HEIGHT, LOG_MAX_LDE)?;
    let batch = &proof.proof;
    let common: &CommonData<Config> = verifier.common_data();
    let airs = verifier.table_airs::<4>().map_err(boxed)?;
    let public_values = verifier.table_public_values(&pis).map_err(boxed)?;
    let pcs = config.pcs();
    let is_zk = <WhirPcs as UnivariateStarkPcs<EF, Challenger>>::ZK;
    let is_zk_usize = usize::from(is_zk);
    let gadget = LogUpGadget::new();
    let all_lookups = common.lookups.as_slice();

    // Per-instance shape, mirroring verify_batch's pre-transcript loop.
    let mut ext_domain_sizes = Vec::new();
    let mut preprocessed_widths = Vec::new();
    let mut log_num_quotient_chunks = Vec::new();
    for (i, air) in airs.iter().enumerate() {
        let (base_db, ext_size) = validate_degree_bits(
            Some(i),
            batch.degree_bits[i],
            is_zk_usize,
            pcs.log_min_trace_height(),
            pcs.log_max_trace_height(),
        )
        .map_err(boxed)?;
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
        let log_chunks = get_log_num_quotient_chunks_for_domain::<_, EF, _, _>(
            air,
            layout,
            pcs.natural_domain_for_degree(1usize << base_db),
            all_lookups[i].as_ref(),
            is_zk_usize,
            &gadget,
        );
        log_num_quotient_chunks.push(log_chunks);
    }

    // Replay the batch transcript to recover the challenges the fold consumes.
    let shape = BatchShape {
        trace_widths: airs.iter().map(BaseAir::<F>::width).collect(),
        public_value_counts: airs.iter().map(BaseAir::<F>::num_public_values).collect(),
        preprocessed_widths: preprocessed_widths.clone(),
        has_preprocessed_commitment: common.preprocessed.is_some(),
        num_lookup_instances: all_lookups.iter().filter(|c| !c.is_empty()).count(),
        lookup_pow_bits: config.lookup_proof_of_work_bits(),
        has_randomization_commitment: is_zk,
        ood_pow_bits: config.ood_proof_of_work_bits(),
    };
    let mut challenger = config.initialise_challenger();
    let mut transcript =
        BatchVerifierTranscript::<Challenger, F, EF, Commitment>::new(&mut challenger, shape);
    transcript.instance_bindings(&batch.degree_bits);
    transcript.main_phase(batch.commitments.main.clone(), &public_values);
    transcript.preprocessed_phase(common.preprocessed.as_ref().map(|g| g.commitment.clone()));
    let laid_out = transcript
        .lookup_phase(all_lookups, &gadget, batch.lookup_pow_witness)
        .map_err(boxed)?;
    let terminal_values: Vec<EF> = batch
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
    let zeta = transcript.ood_phase(batch.ood_pow_witness).map_err(boxed)?;
    let (coms_to_verify, quotient_domains, preprocessed_index) = commitments_with_opening_points(
        &config,
        &airs,
        zeta,
        &batch.commitments,
        &batch.opened_values,
        common,
        &batch.degree_bits,
        &preprocessed_widths,
        &log_num_quotient_chunks,
    )
    .map_err(boxed)?;

    // Finalize the transcript by replaying the delegated opening argument, exactly as
    // `verify_batch` does. Dropping an unfinalized transcript panics, and the WHIR core
    // is what makes these openings sound, so the identity below is only meaningful on
    // top of a verified opening.
    transcript
        .delegate(|ch| {
            pcs.verify_with_preprocessing(
                coms_to_verify,
                &batch.opening_proof,
                ch,
                preprocessed_index,
            )
        })
        .map_err(boxed)?;
    transcript.finish();

    // The cross-AIR terminal sum: no transcript involvement, but the contract checks
    // it too, so it is checked here.
    gadget
        .verify_terminal_sum(&batch.lookup_terminals)
        .map_err(boxed)?;

    let mut instances_json = Vec::new();
    for (i, air) in airs.iter().enumerate() {
        let ov = &batch.opened_values.instances[i];
        let lookups_i = all_lookups[i].as_ref();
        let layout = AirLayout {
            preprocessed_width: preprocessed_widths[i],
            main_width: BaseAir::<F>::width(air),
            num_public_values: BaseAir::<F>::num_public_values(air),
            num_periodic_columns: BaseAir::<F>::num_periodic_columns(air),
            ..Default::default()
        };
        let perm_values: Vec<EF> = batch.lookup_terminals[i].iter().map(|t| t.0).collect();
        let trace_domain = pcs.natural_domain_for_degree(ext_domain_sizes[i] >> is_zk_usize);
        instances_json.push(instance_identity_json::<Config, _>(
            i,
            air,
            layout,
            lookups_i,
            ov,
            &public_values[i],
            trace_domain,
            &quotient_domains[i],
            &laid_out[i],
            &perm_values,
            zeta,
            constraint_alpha,
            &gadget,
        ));
    }
    let doc = json!({
        "description": "Constraint-identity vectors for the settlement batch verifier",
        "field": "KoalaBear",
        "extension": 4,
        "base_trace": BASE_TRACE,
        "degree_bits": batch.degree_bits,
        "zeta": ext_json(&zeta),
        "constraint_alpha": ext_json(&constraint_alpha),
        "instances": instances_json,
    });
    let path = artifact_path();
    std::fs::write(&path, serde_json::to_vec_pretty(&doc)?).map_err(boxed)?;
    // Three u32 words per flattened node.
    let total_nodes: usize = instances_json
        .iter()
        .map(|v| v["nodes"].as_array().map_or(0, |arr| arr.len() / 3))
        .sum();
    println!("wrote {}", path.display());
    println!(
        "instances: {}, total DAG nodes: {}",
        instances_json.len(),
        total_nodes
    );
    Ok(())
}
