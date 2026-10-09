//! The blinding invariant, and this file is the guard.
//!
//! D-092 batch 89 split the two layers apart, so the guard split with them:
//!
//! * The **client / inner** layer (the transfer proof, the base proof the rc
//!   circuit re-verifies) MUST blind. Its trace holds `sk_d`, `rho`, `psi`.
//!   Without blinding the opening argument hands the verifier linear
//!   combinations of those witness cells and the secrets are recoverable by
//!   linear algebra over a public proof.
//! * The **settlement** layer (the STARK of the rc circuit - the one
//!   ShieldedPool verifies on-chain) MUST NOT blind. Its witness is a
//!   deterministic function of public data: the client proof (already ZK, so
//!   its openings are public-safe by construction) and the block statement
//!   (public by design). Blinding hides nothing while doubling the committed
//!   height, the grind bits, and the query count of the one proof that costs
//!   gas.
//!
//! The type-level half of both halves is a `const` assert in `src/lib.rs`, so a
//! flip breaks the build rather than waiting for a test run. What lives here is
//! everything a constant cannot prove: that the inner layer's blinding actually
//! sampled and is reseeded per proof, and that the settlement layer is
//! genuinely deterministic - which is the property the fixed/varying
//! classification of D-092 batch 89 rests on.
//!
//! No Fibonacci anywhere: the traces here are a counter, so a witness bug
//! cannot hide behind a recurrence that happens to be satisfiable.

use p3_air::{AirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{Proof, StarkGenericConfig};

use prover::config::F;
use prover::whir::{config, Config};
use prover::whir_recursion::{InnerWhirConfig, CAP_HEIGHT, LOG_MAX_LDE};

type ExtField = <Config as StarkGenericConfig>::Challenge;

/// Width-1 counter AIR: column starts at 0, increments by 1 each row, the
/// public value is the last row. Deliberately trivial - these tests assert a
/// property of the PROOF SHAPE, and a simple witness keeps a failure
/// attributable.
#[derive(Clone, Copy, Debug)]
struct CounterAir;

impl<F> p3_air::BaseAir<F> for CounterAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: p3_air::AirBuilder> p3_air::Air<AB> for CounterAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (a, b) = (main.current_slice()[0], main.current_slice()[1]);
        let (a_next, b_next) = (main.next_slice()[0], main.next_slice()[1]);
        let public: AB::Expr = builder.public_values()[0].into();
        // a counts by 1, b counts by 2: two independent columns so a
        // mis-strided trace cannot satisfy both.
        builder.when_first_row().assert_eq(a, AB::F::ZERO);
        builder.when_first_row().assert_eq(b, AB::F::ZERO);
        builder.when_transition().assert_eq(a + AB::F::ONE, a_next);
        builder.when_transition().assert_eq(b + (AB::F::ONE + AB::F::ONE), b_next);
        builder.when_last_row().assert_eq(a, public);
    }
}

fn counter(len: usize) -> (p3_matrix::dense::RowMajorMatrix<F>, Vec<F>) {
    let mut values = vec![F::ZERO; len * 2];
    for i in 1..len {
        values[i * 2] = values[(i - 1) * 2] + F::ONE;
        values[i * 2 + 1] = values[(i - 1) * 2 + 1] + F::ONE + F::ONE;
    }
    let last_a = values[values.len() - 2];
    (p3_matrix::dense::RowMajorMatrix::new(values, 2), vec![last_a])
}

/// Trace size for the settlement-layer checks. Small on purpose: these tests
/// assert a proof-shape property, and a small trace makes it cheap on every
/// `cargo test`.
const LOG_ROWS: usize = 8;
/// LDE ceiling for those same tests. Must clear the trace height plus the
/// quotient expansion.
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

/// The settlement layer ships NO blinding: no random commitment, no random
/// openings, and the verifier accepts it (because `Pcs::ZK` is false, so the
/// verifier's shape check expects exactly this).
#[test]
fn settlement_proof_carries_no_blinding() {
    let cfg = config(0, BENCH_LDE).expect("settlement config");
    let air = CounterAir;
    let (trace, pis) = counter(1 << LOG_ROWS);
    let proof: Proof<Config> = p3_uni_stark::prove(&cfg, &air, trace, &pis).expect("prove");
    p3_uni_stark::verify(&cfg, &air, &proof, &pis).expect("verify");

    assert!(
        proof.commitments.random.is_none(),
        "the settlement layer must not blind: its witness is public-derived"
    );
    assert!(
        proof.opened_values.random.is_none(),
        "the settlement layer must not open random columns"
    );
}

/// The load-bearing consequence: settlement proving is DETERMINISTIC. Two
/// proofs of the same statement are byte-identical.
///
/// This is what the fixed/varying classification of D-092 batch 89 depends on -
/// with no blinding the transcript has no private randomness left, so the
/// fixed/varying split is a property of the protocol (the phase marks) rather
/// than of a pair of sampled runs. If a future change reintroduces any
/// per-proof randomness into the settlement layer, this test fails and the
/// classifier must go back to the two-run diff.
#[test]
fn settlement_proving_is_deterministic() {
    let cfg = config(0, BENCH_LDE).expect("settlement config");
    let air = CounterAir;

    let (t1, p1) = counter(1 << LOG_ROWS);
    let a: Proof<Config> = p3_uni_stark::prove(&cfg, &air, t1, &p1).expect("prove a");
    let (t2, p2) = counter(1 << LOG_ROWS);
    let b: Proof<Config> = p3_uni_stark::prove(&cfg, &air, t2, &p2).expect("prove b");

    assert_eq!(p1, p2, "both proofs must be of the same statement");
    assert_eq!(
        wire_bytes(&a),
        wire_bytes(&b),
        "two settlement proofs of the same statement differ: the settlement
         layer picked up per-proof randomness, which breaks the structural
         fixed/varying classification and inflates the on-chain proof"
    );

    // The control that keeps the byte-equality honest: both verify against the
    // same public inputs.
    p3_uni_stark::verify(&cfg, &air, &a, &p1).expect("a verifies");
    p3_uni_stark::verify(&cfg, &air, &b, &p2).expect("b verifies");
}

/// The inner layer - the one that holds the secrets - still blinds, and blinds
/// freshly every time.
///
/// Two inner proofs of an identical statement must differ, because each draws
/// fresh randomness. This is the only check that catches a fixed RNG seed: a
/// deterministic blinding passes every single-proof assertion while being
/// worthless, since the mask is then reproducible by anyone who knows the seed.
#[test]
fn inner_layer_blinding_is_random_across_proofs() {
    let inner = InnerWhirConfig::new(LOG_MAX_LDE, CAP_HEIGHT).expect("inner config");
    let air = CounterAir;

    let (t1, p1) = counter(1 << LOG_ROWS);
    let a: Proof<InnerWhirConfig> = p3_uni_stark::prove(&inner, &air, t1, &p1).expect("prove a");
    let (t2, p2) = counter(1 << LOG_ROWS);
    let b: Proof<InnerWhirConfig> = p3_uni_stark::prove(&inner, &air, t2, &p2).expect("prove b");

    assert_eq!(p1, p2, "both proofs must be of the same statement");

    let ra = a.commitments.random.as_ref().expect("the inner layer must blind");
    let rb = b.commitments.random.as_ref().expect("the inner layer must blind");
    assert!(
        a.opened_values.random.is_some(),
        "the inner layer must open its random columns"
    );
    assert_ne!(
        wire_bytes(ra),
        wire_bytes(rb),
        "two inner proofs of the same statement share a random commitment: the
         blinding RNG is not being reseeded, so the mask is reproducible and leaks"
    );

    // Stronger than it looks: the trace commitment must ALSO differ. Under
    // this PCS the mask rows are folded into the committed matrix, so the
    // trace commitment is itself per-proof fresh - two inner proofs of the
    // same statement are unlinkable at the commitment level, not just at the
    // opening level.
    assert_ne!(
        wire_bytes(&a.commitments.trace),
        wire_bytes(&b.commitments.trace),
        "inner blinding must randomise the committed trace, not just the R commitment"
    );

    // Non-zero openings: an all-zero "randomness" is the signature of a
    // blinding path that allocated the columns but never sampled them.
    let opened = a.opened_values.random.as_ref().expect("checked above");
    assert!(!opened.is_empty(), "random openings must not be empty");
    assert!(
        opened.iter().any(|v: &ExtField| *v != ExtField::ZERO),
        "random openings are all zero: blinding allocated but never sampled"
    );

    p3_uni_stark::verify(&inner, &air, &a, &p1).expect("a verifies");
    p3_uni_stark::verify(&inner, &air, &b, &p2).expect("b verifies");
}

/// The recursion layer must build over a BLINDED base proof and settle it with
/// an UNBLINDED settlement proof.
///
/// This is the load-bearing one for the bridge: it pins both halves of the
/// split invariant in one path. The in-circuit verifier mirrors the native one,
/// which rejects a base proof whose blinding shape disagrees with the inner
/// `Pcs::ZK`; the settlement it produces must carry no R commitment.
#[test]
fn recursion_settles_a_blinded_base_proof() {
    // 1024, not smaller. The in-circuit verifier rejects a saturated STIR
    // query count: at a 256-row base trace the final folded domain is 128
    // while the schedule asks for 182 queries, and
    // `pcs/whir/params.rs:61` refuses with
    // "saturating STIR query counts are not yet supported in-circuit".
    // That is a real deployment floor on base-proof size, so the number here
    // is a supported size rather than an arbitrary small one.
    const BASE_TRACE: usize = 1024;

    use prover::whir_recursion::{build_recursion_circuit, settle_recursion_circuit};

    let inner = InnerWhirConfig::new(LOG_MAX_LDE, CAP_HEIGHT).expect("inner config");
    let air = CounterAir;
    let (trace, pis) = counter(BASE_TRACE);

    let base = p3_uni_stark::prove(&inner, &air, trace.clone(), &pis).expect("base prove");
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

    // And the whole two-layer path must still work on that blinded base.
    let rc = build_recursion_circuit(&inner, &air, &base, &pis)
        .expect("recursion circuit must build over a BLINDED base proof");
    let (proof, verifier) = settle_recursion_circuit(&rc, LOG_MAX_LDE).expect("settle");
    verifier
        .verify(&proof, &pis)
        .expect("settlement must accept a recursion proof over a blinded base");

    // The settlement itself carries no blinding (batch 89).
    assert!(
        proof.proof.commitments.random.is_none(),
        "the settlement proof must not blind"
    );

    // Statement binding survives the split: the base proof's mask must not
    // become a way to make the settlement accept a different statement.
    let mut tampered = pis.clone();
    if let Some(last) = tampered.last_mut() {
        *last += F::ONE;
    }
    assert!(
        verifier.verify(&proof, &tampered).is_err(),
        "settlement must reject a different statement even with a blinded base"
    );
}
