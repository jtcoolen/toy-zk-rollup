//! HVZK blinding is mandatory, and this file is the guard.
//!
//! A shielded pool whose proof opens the trace without blinding leaks its
//! secrets: the verifier is handed linear combinations of witness cells at a
//! random point, and with enough queries the witness is recoverable by linear
//! algebra over the published proof. So "the prover runs with ZK on" is not a
//! deployment detail that whoever assembles the config can be trusted with. It
//! is a property of the proof bytes, and it has to fail closed.
//!
//! Four assertions, cheapest first:
//!
//!   1. `Pcs::ZK` is true for BOTH configs. A compile-time constant, so an
//!      upstream bump that flips it back fails here instead of shipping.
//!   2. A real proof carries `commitments.random` and `opened_values.random`,
//!      and they are non-trivial. The wire-level check: the branch ran, and it
//!      sampled rather than zero-filled.
//!   3. Two proofs of the same statement differ. A prover with a constant seed
//!      would pass every single-proof check and still leak, because reproducible
//!      blinding is not blinding.
//!   4. The recursion layer builds and settles over a BLINDED base proof, so the
//!      in-circuit verifier is exercised against the shape the pool produces.
//!
//! The type-level guarantee (`Pcs::ZK` on both layers) is NOT here: it is a
//! `const` assert in `src/lib.rs`, so it breaks the build rather than waiting
//! for a test run. What is left here is everything a constant cannot prove --
//! that blinding ran, that it sampled real randomness, and that it is reseeded
//! per proof.

use p3_air::{AirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{Proof, StarkGenericConfig};

use prover::config::F;
use prover::whir::{config, Config};
use prover::whir_recursion::{InnerWhirConfig, CAP_HEIGHT, LOG_MAX_LDE};

type ExtField = <Config as StarkGenericConfig>::Challenge;

/// Width-2 Fibonacci AIR: first row pinned to (1,1), public value is the last
/// row's `a`. Same shape as the throughput harness.
#[derive(Clone, Copy, Debug)]
struct FibAir;

impl<F> p3_air::BaseAir<F> for FibAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: p3_air::AirBuilder> p3_air::Air<AB> for FibAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
        let (a_next, b_next) = (main.next_slice()[0], main.next_slice()[1]);
        let two = AB::F::ONE + AB::F::ONE;
        let public: AB::Expr = builder.public_values()[0].into();
        builder.when_first_row().assert_eq(a, AB::F::ONE);
        builder.when_first_row().assert_eq(b, AB::F::ONE);
        builder.when_transition().assert_eq(a + b, a_next);
        builder.when_transition().assert_eq(a + b * two, b_next);
        builder.when_last_row().assert_eq(a, public);
    }
}

fn fib(len: usize) -> (p3_matrix::dense::RowMajorMatrix<F>, Vec<F>) {
    let mut values = vec![F::ONE; len * 2];
    for i in 1..len {
        let a = values[(i - 1) * 2];
        let b = values[(i - 1) * 2 + 1];
        values[i * 2] = a + b;
        values[i * 2 + 1] = a + (b + b);
    }
    let last_a = values[values.len() - 2];
    (
        p3_matrix::dense::RowMajorMatrix::new(values, 2),
        vec![last_a],
    )
}

/// Trace size for the settlement-layer checks. Small on purpose: these tests
/// assert a security property, and a small trace makes that property cheap to
/// check on every `cargo test`.
const LOG_ROWS: usize = 8;
/// LDE ceiling for those same tests. Must clear the trace height plus the ZK
/// doubling and the quotient expansion, so it sits well above `LOG_ROWS`.
const BENCH_LDE: usize = 16;

/// Commitments compared by their wire bytes.
///
/// `MerkleCap` does not implement `PartialEq`, and reaching for `Debug`
/// formatting would compare a rendering rather than the value. postcard is the
/// settlement wire format, so byte equality here is exactly the equality the
/// chain would see.
fn wire_bytes<C: serde::Serialize>(c: &C) -> Vec<u8> {
    postcard::to_allocvec(c).expect("commitment should serialize")
}

/// The wire-level guarantee: a real proof carries the random commitment and the
/// random openings, and both are non-trivial.
///
/// `p3-uni-stark` models both as `Option` and its own verifier rejects a
/// proof whose `Option`-ness disagrees with `Pcs::ZK`. Asserting `Some` is
/// what separates "blinding is compiled in" from "blinding actually ran", and
/// the non-zero checks below are what separate "ran" from "allocated zeros".
#[test]
fn settlement_proof_carries_non_trivial_blinding() {
    let cfg = config(0, BENCH_LDE).expect("settlement config");
    let air = FibAir;
    let (trace, pis) = fib(1 << LOG_ROWS);
    let proof: Proof<Config> = p3_uni_stark::prove(&cfg, &air, trace, &pis).expect("prove");
    p3_uni_stark::verify(&cfg, &air, &proof, &pis).expect("verify");

    let random = proof
        .commitments
        .random
        .as_ref()
        .expect("a blinded proof must carry a random commitment");
    assert!(
        proof.opened_values.random.is_some(),
        "a blinded proof must open its random columns"
    );

    // The random commitment must be distinct from the trace commitment. If the
    // prover padded with zeros instead of sampling, the two could coincide and
    // nothing would be hidden.
    assert_ne!(
        wire_bytes(random),
        wire_bytes(&proof.commitments.trace),
        "random commitment must differ from the trace commitment"
    );

    // Non-zero openings: an all-zero "randomness" is the signature of a blinding
    // path that allocated the columns but never sampled them.
    let opened = proof.opened_values.random.as_ref().expect("checked above");
    assert!(!opened.is_empty(), "random openings must not be empty");
    assert!(
        opened.iter().any(|v: &ExtField| *v != ExtField::ZERO),
        "random openings are all zero: blinding allocated but never sampled"
    );
}

/// Blinding must be random, not merely present.
///
/// Two proofs of an identical statement must differ, because each draws fresh
/// randomness. This is the only check that catches a fixed RNG seed: a
/// deterministic blinding passes every single-proof assertion above while being
/// worthless, since the mask is then reproducible by anyone who knows the seed.
#[test]
fn blinding_is_random_across_proofs() {
    let cfg = config(0, BENCH_LDE).expect("settlement config");
    let air = FibAir;

    let (t1, p1) = fib(1 << LOG_ROWS);
    let a: Proof<Config> = p3_uni_stark::prove(&cfg, &air, t1, &p1).expect("prove a");
    let (t2, p2) = fib(1 << LOG_ROWS);
    let b: Proof<Config> = p3_uni_stark::prove(&cfg, &air, t2, &p2).expect("prove b");

    // Same statement, or the proofs would differ for a boring reason and this
    // test would prove nothing.
    assert_eq!(p1, p2, "both proofs must be of the same statement");

    let ra = a.commitments.random.as_ref().expect("a is blinded");
    let rb = b.commitments.random.as_ref().expect("b is blinded");
    assert_ne!(
        wire_bytes(ra),
        wire_bytes(rb),
        "two proofs of the same statement share a random commitment: the blinding
         RNG is not being reseeded, so the mask is reproducible and leaks"
    );

    // Stronger than it looks: the trace commitment must ALSO differ. Under
    // this PCS the mask rows are folded into the committed matrix, so the
    // trace commitment is itself per-proof fresh. That is a better property
    // than only the R commitment being fresh -- it means two proofs of the
    // same statement are unlinkable at the commitment level, not just at the
    // opening level.
    assert_ne!(
        wire_bytes(&a.commitments.trace),
        wire_bytes(&b.commitments.trace),
        "blinding must randomise the committed trace, not just the R commitment"
    );

    // The control that keeps the two asserts above honest: both proofs must
    // verify against the SAME public inputs. If they did not, every difference
    // above would be explained by proving a different statement.
    p3_uni_stark::verify(&cfg, &air, &a, &p1).expect("a verifies");
    p3_uni_stark::verify(&cfg, &air, &b, &p2).expect("b verifies");
}

/// The recursion layer must build and settle over a BLINDED base proof.
///
/// This is the load-bearing one for the bridge. The in-circuit verifier mirrors
/// the native one, which rejects a proof whose blinding shape disagrees with
/// `Pcs::ZK`. If the recursive path were only ever exercised against unblinded
/// proofs, the R-round handling would go untested in exactly the configuration
/// the shielded pool ships.
#[test]
fn recursion_settles_a_blinded_base_proof() {
    use p3_circuit::test_utils::{generate_trace_rows, FibonacciAir};
    use prover::whir_recursion::{build_recursion_circuit, settle_recursion_circuit};

    // 1024, not smaller. The in-circuit verifier rejects a saturated STIR
    // query count: at a 256-row base trace the final folded domain is 128
    // while the schedule asks for 182 queries, and
    // `pcs/whir/params.rs:61` refuses with
    // "saturating STIR query counts are not yet supported in-circuit".
    // That is a real deployment floor on base-proof size, so the number here
    // is a supported size rather than an arbitrary small one.
    const BASE_TRACE: usize = 1024;

    let inner = InnerWhirConfig::new(LOG_MAX_LDE, CAP_HEIGHT).expect("inner config");
    let air = FibonacciAir {};
    let trace = generate_trace_rows::<F>(0, 1, BASE_TRACE);
    let mut a = F::ZERO;
    let mut b = F::ONE;
    for _ in 1..BASE_TRACE {
        let next = a + b;
        a = b;
        b = next;
    }
    let pis = vec![F::ZERO, F::ONE, b];

    let base = p3_uni_stark::prove(&inner, &air, trace, &pis).expect("base prove");
    p3_uni_stark::verify(&inner, &air, &base, &pis).expect("base verify");

    // Blinded before it is ever recursed over.
    assert!(
        base.commitments.random.is_some(),
        "the base proof must be blinded before recursion"
    );
    assert!(
        base.opened_values.random.is_some(),
        "the base proof must open its random columns"
    );

    // And the whole two-layer path must still work on that blinded proof.
    let rc = build_recursion_circuit(&inner, &air, &base, &pis)
        .expect("recursion circuit must build over a BLINDED base proof");
    let (proof, verifier) = settle_recursion_circuit(&rc, LOG_MAX_LDE).expect("settle");
    verifier
        .verify(&proof, &pis)
        .expect("settlement must accept a recursion proof over a blinded base");

    // Statement binding survives blinding: the mask must not become a way to
    // make the settlement accept a different statement.
    let tampered = vec![F::ZERO, F::ONE, b + F::ONE];
    assert!(
        verifier.verify(&proof, &tampered).is_err(),
        "settlement must reject a different statement even with blinding active"
    );
}
