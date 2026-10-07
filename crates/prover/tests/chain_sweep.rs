//! Parameterized layer-chain sweep (D-092 proof-size work).
//!
//! Same chain as `recursion_chain::layer_chain_convergence` but every knob
//! comes from the environment so a grid can run without recompiling:
//!
//!   `WHIR_BASE_TRACE`   base fib trace rows        (default 1024)
//!   `WHIR_LDE`          chain log-max-LDE budget   (default 24)
//!   `WHIR_RATE_INNER`   starting inverse rate, inner layers (default 1)
//!   `WHIR_RATE_FINAL`   starting inverse rate, final layer  (default 1)
//!
//! Prints every layer size, the final postcard size, and the final flat
//! (WBND) size when `WHIR_EMIT_FLAT`=1. Run:
//!   `WHIR_RATE_INNER`=2 cargo test --release -p prover --test `chain_sweep` -- --ignored --nocapture --test-threads=1

use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
use p3_field::PrimeCharacteristicRing;
use prover::config::F;
use prover::whir_recursion::{
    build_batch_recursion_circuit, build_recursion_circuit, settle_recursion_circuit_with,
    InnerWhirConfig,
};

fn env_or(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

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

#[test]
#[ignore = "parameter sweep; run with --release"]
fn chain_sweep() {
    let base_trace = env_or("WHIR_BASE_TRACE", 1024);
    let lde = env_or("WHIR_LDE", 24);
    let rate_inner = env_or("WHIR_RATE_INNER", 1);
    let rate_final = env_or("WHIR_RATE_FINAL", 1);
    let layers = env_or("WHIR_LAYERS", 2);
    let cap = env_or("WHIR_CAP", 0);
    println!(
        "sweep: base={base_trace} lde={lde} rate_inner={rate_inner} rate_final={rate_final} layers={layers} cap={cap}"
    );

    let inner = InnerWhirConfig::new_with(lde, cap, rate_inner).expect("inner config");
    let air = FibonacciAir {};
    let trace = generate_trace_rows::<F>(0, 1, base_trace);
    let pis = vec![F::ZERO, F::ONE, fibonacci_output(base_trace)];

    let base = p3_uni_stark::prove(&inner, &air, trace, &pis).expect("base prove");
    let base_bytes = postcard::to_allocvec(&base).map_or(0, |v| v.len());
    println!("layer 0 (base fib proof)  {base_bytes:>9} B");

    let mut rc = build_recursion_circuit(&inner, &air, &base, &pis).expect("rc1");
    let mut prev_bytes = base_bytes;

    for layer in 1..=layers {
        let (proof, verifier) =
            settle_recursion_circuit_with(&rc, inner.clone()).expect("settle InSC");
        verifier.verify(&proof, &pis).expect("InSC layer verifies");
        let bytes = postcard::to_allocvec(&proof).map_or(0, |v| v.len());
        println!("layer {layer} (InSC settle)   {bytes:>9} B");
        prev_bytes = bytes;
        rc = build_batch_recursion_circuit(&inner, &verifier, &proof, &pis)
            .expect("next recursion circuit");
    }

    // Final layer under the Keccak config at the requested rate.
    let settlement = prover::whir::config_with(cap, lde, rate_final);
    match settlement {
        Ok(cfg) => {
            let (proof, verifier) = settle_recursion_circuit_with(&rc, cfg).expect("settle Keccak");
            verifier
                .verify(&proof, &pis)
                .expect("Keccak settle verifies");
            let bytes = postcard::to_allocvec(&proof).map_or(0, |v| v.len());
            println!("final   (Keccak settle) {bytes:>9} B  (from {prev_bytes} B)");
            let bad = vec![F::ZERO, F::ONE, fibonacci_output(base_trace) + F::ONE];
            assert!(
                verifier.verify(&proof, &bad).is_err(),
                "must reject other statement"
            );
        }
        Err(e) => println!("final   (Keccak settle) INFEASIBLE: {e:?}"),
    }
}
