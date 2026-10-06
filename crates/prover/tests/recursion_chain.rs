//! Layer-chain convergence: how small does the proof get when each layer
//! re-verifies the previous one? (D-092 M1 step 1.)
//!
//! Intermediate layers settle under the Poseidon2 `InSC` so the next
//! [`build_batch_recursion_circuit`] can consume them; the final layer settles
//! under the Keccak `OutSC`, which is what the Solidity verifier replays.
//! Run: `cargo test --release -p prover --test recursion_chain -- --ignored --nocapture --test-threads=1`

use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
use p3_field::PrimeCharacteristicRing;
use prover::config::F;
use prover::whir_recursion::{
    build_batch_recursion_circuit, build_recursion_circuit, settle_recursion_circuit,
    settle_recursion_circuit_with, InnerWhirConfig, CAP_HEIGHT,
};

const BASE_TRACE: usize = 1024;

/// Starting inverse rate for the final (Keccak) settlement of the exported
/// chain bundle. Rate 2 halves the STIR query budget - the dominant term of
/// the on-chain wire - and the final circuit fits it under TWO_ADICITY 24
/// (D-092 batch 20). Set WHIR_RATE_FINAL=1 to reproduce the rate-1 baseline.
fn rate_final() -> usize {
    std::env::var("WHIR_RATE_FINAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2)
}

/// Starting inverse rate for the inner (Poseidon2) layers. Rate 2 shrinks
/// every intermediate proof (fewer queries -> shorter paths -> fewer
/// Poseidon2 rows in the next circuit), which is what buys the final layer
/// its rate headroom (D-092 batch 20).
fn rate_inner() -> usize {
    std::env::var("WHIR_RATE_INNER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2)
}

/// The recursion circuit's own trace grows with the inner proof it re-verifies
/// (every Merkle path node is a Poseidon2 row), so the chain needs a larger
/// LDE budget than the single-layer tests: layer 2 overflows 2^22 with
/// `PowBitsExceedBudget` { required: 19, budget: 18 }.
const CHAIN_LOG_MAX_LDE: usize = 24;

fn fibonacci_output(n: usize) -> F {
    let mut a = F::ZERO;
    let mut b = F::ONE;
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    b
}

/// Size ratio in per-mille, integer math (clippy dislikes f64 casts of usize).
const fn per_mille(bytes: usize, prev: usize) -> usize {
    bytes * 1000 / prev
}

#[test]
#[ignore = "layer-chain harness; run with --release"]
fn layer_chain_convergence() {
    let inner = InnerWhirConfig::new_with(CHAIN_LOG_MAX_LDE, CAP_HEIGHT, rate_inner())
        .expect("inner config");
    let air = FibonacciAir {};
    let trace = generate_trace_rows::<F>(0, 1, BASE_TRACE);
    let pis = vec![F::ZERO, F::ONE, fibonacci_output(BASE_TRACE)];

    let base = p3_uni_stark::prove(&inner, &air, trace, &pis).expect("base prove");
    let base_bytes = postcard::to_allocvec(&base).map_or(0, |v| v.len());
    println!("layer 0 (base fib proof)      {base_bytes:>9} B");

    let mut rc = build_recursion_circuit(&inner, &air, &base, &pis).expect("rc1");
    let mut prev_bytes = base_bytes;

    // Intermediate layers: settle under the InSC, recurse again.
    for layer in 1..=4usize {
        let (proof, verifier) =
            settle_recursion_circuit_with(&rc, inner.clone()).expect("settle InSC");
        verifier
            .verify(&proof, &pis)
            .expect("InSC layer verifies against the same statement");
        let bytes = postcard::to_allocvec(&proof).map_or(0, |v| v.len());
        println!(
            "layer {layer} (InSC settle)         {bytes:>9} B  (x{}.{:03})",
            per_mille(bytes, prev_bytes) / 1000,
            per_mille(bytes, prev_bytes) % 1000
        );
        prev_bytes = bytes;
        rc = build_batch_recursion_circuit(&inner, &verifier, &proof, &pis)
            .expect("next recursion circuit");
    }

    // Final layer: settle under the Keccak OutSC - the on-chain shape.
    let (proof, verifier) =
        settle_recursion_circuit(&rc, CHAIN_LOG_MAX_LDE).expect("settle Keccak");
    verifier
        .verify(&proof, &pis)
        .expect("Keccak settle verifies");
    let bytes = postcard::to_allocvec(&proof).map_or(0, |v| v.len());
    println!(
        "final   (Keccak settle)       {bytes:>9} B  (x{}.{:03})",
        per_mille(bytes, prev_bytes) / 1000,
        per_mille(bytes, prev_bytes) % 1000
    );
    // Tamper check: the statement binding survives the chain.
    let bad = vec![F::ZERO, F::ONE, fibonacci_output(BASE_TRACE) + F::ONE];
    assert!(
        verifier.verify(&proof, &bad).is_err(),
        "must reject other statement"
    );
}

/// M1 step 2: export the final-layer recursion circuit through the composed
/// bundle path so the EXISTING Solidity verifier can be measured against a
/// real multi-layer recursion proof. Writes the WBND bundle + a small
/// sidecar (statement) into contracts/test/vectors/.
#[test]
#[ignore = "writes vectors; run with --release when regenerating"]
fn export_chain_bundle() {
    let inner = InnerWhirConfig::new_with(CHAIN_LOG_MAX_LDE, CAP_HEIGHT, rate_inner())
        .expect("inner config");
    let air = FibonacciAir {};
    let trace = generate_trace_rows::<F>(0, 1, BASE_TRACE);
    let pis = vec![F::ZERO, F::ONE, fibonacci_output(BASE_TRACE)];

    let base = p3_uni_stark::prove(&inner, &air, trace, &pis).expect("base prove");
    let mut rc = build_recursion_circuit(&inner, &air, &base, &pis).expect("rc1");
    // Two InSC layers: the plateau is reached at layer 2 (762 KB vs 766 KB
    // at layer 4), so two layers is the honest shape at minimum wall time.
    for _ in 1..=2 {
        let (proof, verifier) =
            settle_recursion_circuit_with(&rc, inner.clone()).expect("settle InSC");
        verifier.verify(&proof, &pis).expect("InSC layer verifies");
        rc = build_batch_recursion_circuit(&inner, &verifier, &proof, &pis)
            .expect("next recursion circuit");
    }

    let (bundle, jj, blob) =
        prover::composed_export::settlement_bundle_with_blob(&rc, &pis, rate_final())
            .expect("composed bundle for the chain");
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/test/vectors");
    // The vectors doc too: gen_composed_flat.mjs turns it into the flat form
    // the WhirComposed harness drives (WHIR_FLAT env, batch 19).
    std::fs::write(
        format!("{dir}/recursion_chain_vectors.json"),
        jj.to_string(),
    )
    .expect("write vectors");
    std::fs::write(format!("{dir}/recursion_chain_vectors.bin"), &blob).expect("write blob");
    std::fs::write(format!("{dir}/recursion_chain_bundle.bin"), &bundle).expect("write bundle");
    let stmt: Vec<u64> = pis
        .iter()
        .map(p3_field::PrimeField64::as_canonical_u64)
        .collect();
    let sidecar = serde_json::json!({ "statement": stmt, "bundle_len": bundle.len() });
    std::fs::write(
        format!("{dir}/recursion_chain_sidecar.json"),
        sidecar.to_string(),
    )
    .expect("write sidecar");
    println!("bundle {} B, statement {:?}", bundle.len(), stmt);
}
