//! Prover throughput harness.
//!
//! ```text
//! cargo test --release -p prover --test prover_bench -- --ignored --nocapture
//! ```
//!
//! Deliberately not `criterion`: it is not in `Cargo.lock`, and this workspace
//! builds offline from a vendored registry. A STARK proof takes seconds, not
//! nanoseconds, so wall-clock over a couple of iterations is the right
//! instrument anyway - criterion would spend longer on warmup than the
//! measurement deserves.
//!
//! What is timed is the whole settlement path: `p3_uni_stark::prove` through
//! the WHIR PCS, and `verify` on the other side. The AIR is Fibonacci of width
//! 2, which is deliberately minimal - the point is the proving system cost
//! (LDE, Merkle, WHIR folding, grinding), not AIR evaluation, so a wider AIR
//! would only add a term that is not the one under study.
//!
//! The config is sized at the LDE ceiling and reused for smaller traces,
//! mirroring the node: one config per deployment, built at the largest batch
//! it will see.

use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use prover::config::F;
use prover::whir::config;

/// `a' = a + b`, `b' = a + 2b`, first row pinned by one public value.
#[derive(Clone, Copy, Debug)]
struct FibAir;

// Bounded (`F: Field`) this would make `Air<AB>` unsatisfiable: `AB::F` is only
// known to be a `Field` through the `AirBuilder` chain, which Rust will not carry
// back into a separate impl.
impl<F> BaseAir<F> for FibAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder> Air<AB> for FibAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
        let (a_next, b_next) = (main.next_slice()[0], main.next_slice()[1]);
        let two = AB::F::ONE + AB::F::ONE;
        let public: AB::Expr = builder.public_values()[0].into();
        // First row pinned to (1,1); the public value is the LAST row's `a`.
        // Pinning the public to the first row instead is an
        // `OodEvaluationMismatch` that only shows up at verify time.
        builder.when_first_row().assert_eq(a, AB::F::ONE);
        builder.when_first_row().assert_eq(b, AB::F::ONE);
        builder.when_transition().assert_eq(a + b, a_next);
        builder.when_transition().assert_eq(a + b * two, b_next);
        builder.when_last_row().assert_eq(a, public);
    }
}

fn fib_trace(len: usize) -> (RowMajorMatrix<F>, [F; 1]) {
    let mut values = vec![F::ONE; len * 2];
    for i in 1..len {
        let a = values[(i - 1) * 2];
        let b = values[(i - 1) * 2 + 1];
        values[i * 2] = a + b;
        values[i * 2 + 1] = a + (b + b);
    }
    let last_a = values[values.len() - 2];
    (RowMajorMatrix::new(values, 2), [last_a])
}

/// `(log_trace, config_lde, iterations)`. The config LDE is the ceiling the
/// schedule is sized at, which must be at least what the prover actually
/// stacks to for that trace - the ZK doubling and quotient expansion push it
/// above the raw trace height.
const CASES: &[(usize, usize, usize)] = &[(12, 22, 3), (16, 22, 3), (20, 24, 2), (22, 26, 1)];

#[test]
#[ignore = "prover throughput harness; run with --release"]
fn prover_throughput() {
    println!(
        "{:>9} {:>11} {:>11} {:>13} {:>12}",
        "log_rows", "prove_ms", "verify_ms", "proof_bytes", "bytes/row"
    );

    for &(log_rows, lde, iters) in CASES {
        let cfg = config(0, lde).expect("config should build");
        let air = FibAir;
        let rows = 1usize << log_rows;

        let mut prove_ms = Vec::new();
        let mut verify_ms = Vec::new();
        let mut bytes = 0usize;

        for _ in 0..iters {
            let (trace, pis) = fib_trace(rows);

            let t = Instant::now();
            let proof = p3_uni_stark::prove(&cfg, &air, trace, &pis).expect("prove");
            prove_ms.push(t.elapsed().as_secs_f64() * 1e3);

            let t = Instant::now();
            p3_uni_stark::verify(&cfg, &air, &proof, &pis).expect("verify");
            verify_ms.push(t.elapsed().as_secs_f64() * 1e3);

            // The calldata the chain pays for. postcard is the settlement wire
            // format, so this is the number that decides on-chain feasibility.
            bytes = postcard::to_allocvec(&proof).expect("serialize").len();
        }

        prove_ms.sort_by(|a, b| a.partial_cmp(b).expect("times are comparable"));
        verify_ms.sort_by(|a, b| a.partial_cmp(b).expect("times are comparable"));
        let median = |v: &[f64]| v[v.len() / 2];

        println!(
            "{:>9} {:>11.1} {:>11.3} {:>13} {:>12.2}",
            log_rows,
            median(&prove_ms),
            median(&verify_ms),
            bytes,
            // Both fit u32 by a wide margin (proofs are megabytes at most),
            // and routing through u32 keeps the f64 conversion exact.
            f64::from(u32::try_from(bytes).expect("proof fits in u32 bytes"))
                / f64::from(u32::try_from(rows).expect("row count fits in u32"))
        );
    }
}
