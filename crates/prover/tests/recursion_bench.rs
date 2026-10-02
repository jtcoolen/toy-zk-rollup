//! Recursive-proving throughput harness.
//!
//! ```text
//! cargo test --release -p prover --test recursion_bench -- --ignored --nocapture
//! ```
//!
//! Times each stage of the two-layer architecture separately, because they are
//! different costs paid by different parties:
//!
//! ```text
//!   1. base prove      Poseidon2 WHIR   prover, per batch
//!   2. circuit build   recursion        prover, per batch (witnessing dominates)
//!   3. settle prove    Keccak WHIR      prover, per settlement tx
//!   4. settle verify   Keccak WHIR      node, per settlement tx
//! ```
//!
//! Stage 3 emits the proof that goes on-chain, so its postcard size is the
//! calldata number that decides whether on-chain verification is feasible.
//! Stages 1 and 2 are prover-side and amortise across a batch.
//!
//! Not `criterion`: it is not in `Cargo.lock` and this workspace builds offline.
//! A recursion proof takes tens of seconds, so one timed run is the honest
//! instrument.

use std::time::Instant;

use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
use p3_field::PrimeCharacteristicRing;

use prover::config::F;
use prover::whir_recursion::{
    build_recursion_circuit, settle_recursion_circuit, InnerWhirConfig, CAP_HEIGHT, LOG_MAX_LDE,
};

/// `b` after `n` steps of the recurrence the upstream AIR encodes.
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
#[ignore = "recursive proving harness; run with --release"]
fn recursion_throughput() {
    // Same shape the recursion tests use: a 1024-row base trace under the
    // Poseidon2 inner config, settled under the Keccak config at LOG_MAX_LDE.
    const BASE_TRACE: usize = 1024;

    let inner = InnerWhirConfig::new(LOG_MAX_LDE, CAP_HEIGHT).expect("inner config");
    let air = FibonacciAir {};
    let trace = generate_trace_rows::<F>(0, 1, BASE_TRACE);
    let pis = vec![F::ZERO, F::ONE, fibonacci_output(BASE_TRACE)];

    let t = Instant::now();
    let base = p3_uni_stark::prove(&inner, &air, trace, &pis).expect("base prove");
    let base_prove = t.elapsed();
    p3_uni_stark::verify(&inner, &air, &base, &pis).expect("base verify");
    let base_bytes = postcard::to_allocvec(&base).map_or(0, |v| v.len());

    let t = Instant::now();
    let rc = build_recursion_circuit(&inner, &air, &base, &pis).expect("build recursion circuit");
    let build = t.elapsed();
    // Circuit size, the two numbers that predict proving cost: ops is the
    // constraint workload, witness_count the trace height the AIR must clear.
    let ops = rc.circuit.ops.len();
    let witnesses = rc.circuit.witness_count;

    let t = Instant::now();
    let (proof, verifier) = settle_recursion_circuit(&rc, LOG_MAX_LDE).expect("settle");
    let settle_prove = t.elapsed();

    let t = Instant::now();
    verifier.verify(&proof, &pis).expect("settlement verify");
    let settle_verify = t.elapsed();

    // The statement binding must survive the bench. A settlement proof that
    // verifies against any public values is not a settlement proof.
    let tampered = vec![F::ZERO, F::ONE, fibonacci_output(BASE_TRACE) + F::ONE];
    assert!(
        verifier.verify(&proof, &tampered).is_err(),
        "settlement verifier must reject a different statement"
    );

    let settle_bytes = postcard::to_allocvec(&proof).map_or(0, |v| v.len());

    println!("base trace rows       {BASE_TRACE}");
    println!("recursion ops           {ops:>18}");
    println!("recursion witnesses     {witnesses:>18}");
    println!();
    println!("{:<26} {:>12} {:>14}", "stage", "seconds", "bytes");
    println!(
        "{:<26} {:>12.2} {:>14}",
        "1. base prove (P2 WHIR)",
        base_prove.as_secs_f64(),
        base_bytes
    );
    println!(
        "{:<26} {:>12.2} {:>14}",
        "2. recursion circuit",
        build.as_secs_f64(),
        "-"
    );
    println!(
        "{:<26} {:>12.2} {:>14}",
        "3. settle prove (Keccak)",
        settle_prove.as_secs_f64(),
        settle_bytes
    );
    println!(
        "{:<26} {:>12.3} {:>14}",
        "4. settle verify (node)",
        settle_verify.as_secs_f64(),
        "-"
    );
    println!();
    println!(
        "total prover seconds {:.2} (stages 1-3, off-chain)",
        base_prove.as_secs_f64() + build.as_secs_f64() + settle_prove.as_secs_f64()
    );
    // Calldata and deployed code are separate budgets. EIP-170 caps the
    // verifier code at 24,576 bytes; proof bytes ride in as calldata at 16 gas
    // per non-zero byte. Reporting one against the other is a category error.
    println!("on-chain calldata {settle_bytes} bytes");
    println!(
        "  ~{} gas of calldata before the verifier itself runs",
        settle_bytes.saturating_mul(16)
    );
}
