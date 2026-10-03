//! How the settlement proof scales with the config it is proven under.
//!
//! ```text
//! cargo test --release -p prover --test recursion_lde_sweep -- --ignored --nocapture
//! ```
//!
//! The recursion circuit for a 1024-row base trace is ~2^17.2 witnesses. Settling
//! it under a 2^22 config is correct but wasteful: WHIR sizes its LDE and query
//! count from the config, so an oversized config buys nothing and pays in proof
//! bytes. Calldata is 16 gas per non-zero byte, so proof size IS the on-chain
//! cost, and this sweep is what picks the settlement config.
//!
//! Why `catch_unwind`. Below a floor the vendored prover does not return `Err`:
//! `pcs/whir/uni/pcs.rs:443` unwraps the schedule check and panics with
//! `PowBitsExceedBudget`. A sweep that stops at the first panic learns nothing
//! about where the floor is, so each config is caught and reported. The floor is
//! a real constraint on deployment, not a curiosity: it says the settlement config
//! cannot be shrunk without bound to save calldata.

use std::panic::AssertUnwindSafe;
use std::time::Instant;

use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
use p3_field::PrimeCharacteristicRing;

use prover::config::F;
use prover::whir_recursion::{
    build_recursion_circuit, settle_recursion_circuit, InnerWhirConfig, CAP_HEIGHT, LOG_MAX_LDE,
};

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

/// Run `f` with panics turned into a message, so one rejected config cannot
/// end the sweep. The hook is restored before returning.
fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    let captured = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = std::sync::Arc::clone(&captured);
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(s) = info.payload().downcast_ref::<&str>() {
            if let Ok(mut g) = sink.lock() {
                *g = (*s).to_string();
            }
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            if let Ok(mut g) = sink.lock() {
                g.clone_from(s);
            }
        }
    }));
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(previous);
    outcome.map_err(|_| {
        captured
            .lock()
            .map_or_else(|_| "panicked".to_string(), |g| g.clone())
    })
}

#[test]
#[ignore = "settlement config sweep; run with --release"]
fn settlement_lde_sweep() {
    const BASE_TRACE: usize = 1024;

    let inner = InnerWhirConfig::new(LOG_MAX_LDE, CAP_HEIGHT).expect("inner config");
    let air = FibonacciAir {};
    let trace = generate_trace_rows::<F>(0, 1, BASE_TRACE);
    let pis = vec![F::ZERO, F::ONE, fibonacci_output(BASE_TRACE)];

    let base = p3_uni_stark::prove(&inner, &air, trace, &pis).expect("base prove");
    let rc = build_recursion_circuit(&inner, &air, &base, &pis).expect("build circuit");
    let witnesses = rc.circuit.witness_count;
    println!(
        "recursion witnesses {witnesses} (~2^{:0.2}), ops {}\n",
        f64::from(witnesses).log2(),
        rc.circuit.ops.len()
    );

    println!(
        "{:>12} {:>10} {:>11} {:>13}",
        "log_max_lde", "prove_s", "verify_ms", "proof_bytes"
    );

    // Walk the whole range so both edges are visible: below the floor the
    // schedule cannot be built, above it the proof only grows.
    for lde in 17..=LOG_MAX_LDE {
        let t = Instant::now();
        let outcome = guarded(|| settle_recursion_circuit(&rc, lde));
        let prove = t.elapsed().as_secs_f64();

        match outcome {
            Ok(Ok((proof, verifier))) => {
                let t = Instant::now();
                verifier.verify(&proof, &pis).expect("verify");
                let verify = t.elapsed().as_secs_f64() * 1e3;

                // A smaller proof that binds nothing is worthless, so re-check
                // the statement binding at every config size.
                let tampered = vec![F::ZERO, F::ONE, fibonacci_output(BASE_TRACE) + F::ONE];
                assert!(
                    verifier.verify(&proof, &tampered).is_err(),
                    "config {lde} accepted a proof against a different statement"
                );

                let bytes = postcard::to_allocvec(&proof).map_or(0, |v| v.len());
                println!("{lde:>12} {prove:>10.2} {verify:>11.3} {bytes:>13}  ok");
            }
            Ok(Err(e)) => {
                println!("{lde:>12} {:>10} {:>11} {:>13}  ERR: {e}", "-", "-", "-");
            }
            Err(msg) => {
                let first = msg.lines().next().unwrap_or("panicked").to_string();
                println!(
                    "{lde:>12} {:>10} {:>11} {:>13}  PANIC: {first}",
                    "-", "-", "-"
                );
            }
        }
    }
}
