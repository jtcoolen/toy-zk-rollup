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

use std::path::PathBuf;

use p3_air::BaseAir;
use p3_batch_stark::CommonData;
use p3_circuit_prover::CircuitVerifier;
use p3_commit::UnivariateStarkPcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use serde_json::json;

use prover::semantic_blob::{classify_observations, replay_blob};
use prover::semantic_trace::SemChallenger;
use prover::whir_recursion::LOG_MAX_LDE;

use prover::settlement_replay::{
    base_json, bus_layout, com_json, dom_json, ext_json, fib_recursion, hex, one_run, Challenge,
    ReplayOut, SemConfig, SemPcs, EXT_DEG, F,
};

/// Independent proving runs; two is the minimum that separates fixed from varying.
const RUNS: usize = 2;

/// One instance's lookup metadata: trusted-setup data, never proof data (D-063).
fn lookup_meta(lookups: &[p3_lookup::Lookup<F>]) -> Vec<serde_json::Value> {
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

/// Smoke: prove the settlement batch under the semantic config, verify natively, replay
/// the phases by hand, and require the two transcript programs to agree.
#[test]
#[ignore = "proves the settlement batch (~5s); the export test runs this as its first step"]
fn settlement_program_equality() {
    let (pis, rc) = fib_recursion();
    let (program, out, _verifier, _proof) = one_run(&pis, &rc, None);
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
        let (program, out, verifier, proof) = one_run(&pis, &rc, None);
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
                "phase_marks": out
                    .phase_marks
                    .iter()
                    .map(|(name, at)| json!({"phase": name, "at": at}))
                    .collect::<Vec<_>>(),
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
